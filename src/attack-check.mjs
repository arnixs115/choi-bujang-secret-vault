// `npm run bundle`이 실행하는 학생의 자기 점검이다. 심판의 판정이 아니다.
// 기록 형식은 src/attack-record.mjs에 있다. 이 파일은 1~11단계의 시험 목록을 들고 있고,
// 실제로 보낸 요청의 결과만 pass/fail로 기록한다. 보내지 않은 시험은 not_run/unverified로 남긴다.
// 토큰, 쿠키, 개인키, 실명, 메모 본문은 기록하지도 출력하지도 않는다.
//
// 시험용 세션(선택): 승인된 기기 세션이 필요한 정상 요청은 아래 환경 변수에 본인이 직접 값을 넣었을 때만
// 보낸다. 값은 요청 헤더에만 쓰이고 기록·출력되지 않는다. 먼저 보내는 사전 시험
// (notes_list_with_device_session)이 통과하지 못하면 유효한 세션을 확보하지 못한 것으로 보고,
// 세션이 필요한 나머지 시험은 보내지 않고 not_run으로 남긴다.
//
// 보내는 요청: 이 점검기는 GET과 HEAD만 보낸다. POST·PUT·PATCH·DELETE 요청이 필요한 시험은
// (격리된 실행 환경에서 쓰기 요청을 보낼 수 없으므로) 요청을 보내지 않고 not_run으로 남긴다.
//   ATTACK_CHECK_LOGIN_TOKEN   로그인 세션 쿠키(__Host-byte-back-session)의 값
//   ATTACK_CHECK_DEVICE_TOKEN  기기 세션 쿠키(__Host-byte-back-device-session)의 값
import {
  ERROR_CODE_PATTERN,
  RECORDABLE_HEADERS,
  REQUEST_ID_HEADERS,
  REQUEST_ID_PATTERN,
  validateAttackRecords,
} from './attack-record.mjs';

export const ATTACK_ENV = Object.freeze({
  login: 'ATTACK_CHECK_LOGIN_TOKEN',
  device: 'ATTACK_CHECK_DEVICE_TOKEN',
});

const REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_DELAY_MS = 150;
// 이번 실행에서 보낼 수 있는 HTTP 요청의 최대 개수. 시험표는 이보다 훨씬 적게 보내도록 짜여 있다.
const DEFAULT_MAX_REQUESTS = 40;
// `.invalid`는 예약된 최상위 도메인이라 실제 사이트가 될 수 없다. 출처 검사를 일부러 어기는 데만 쓴다.
const FOREIGN_ORIGIN = 'https://attacker.invalid';
const PLACEHOLDER_NOTE_ID = '00000000-0000-4000-8000-000000000000';
// verify-login.mjs가 읽는 로그인 쿠키 이름
const LOGIN_COOKIE = '__Host-byte-back-session';
// src/device-session.mjs의 DEVICE_COOKIE와 같은 이름. 점검 파일이 서버 코드를 가져오지 않도록 여기에 둔다.
const DEVICE_COOKIE = '__Host-byte-back-device-session';
const LOGIN_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;
const DEVICE_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NO_STORE = { 'cache-control': 'no-store' };
// 이 점검기가 실제로 보낼 수 있는 메서드. 그 밖의 메서드를 쓰는 시험은 보내지 않는다.
const SENDABLE_METHODS = Object.freeze(['GET', 'HEAD']);

const http = (stage, testId, kind, method, path, expected, expectedStatus, extra = {}) => ({
  type: 'http', stage, testId, kind, method, path, expected, expectedStatus,
  origin: null, auth: 'none', ...extra,
});
// HTTP 요청을 보내지 않는 항목. status는 'not_run' 또는 'unverified'.
const hold = (stage, testId, kind, method, path, expected, expectedStatus, status, reason) => ({
  type: 'hold', stage, testId, kind, method, path, expected, expectedStatus, status, reason,
});

const LOCAL_ONLY = (command) => `로컬 가상 시험(${command})은 따로 있으나 이번 실행에서 실행하지 않았고, 운영 엔진의 실제 판정은 HTTP 응답으로 확인하지 못함`;

// 1~11단계 시험표. 기대 상태·오류 코드는 api/ 와 src/device-handlers.mjs 의 실제 코드에서 읽은 값이다.
const CATALOG = Object.freeze([
  // 1단계 — 기존 /data.json 점검(보존)
  http(1, 'anonymous_note_read', 'normal', 'GET', '/data.json', '비로그인 화면에서 가상 메모를 확인', [200], {
    verify: ({ json, ctx }) => (json?.sampleMarker === ctx.marker && Array.isArray(json.notes) && json.notes.length > 0)
      || '응답에 공개 가상 메모 확인 표시가 없음',
    summarize: (ok, httpStatus) => (ok
      ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
      : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${httpStatus})`),
  }),

  // 2단계 — 배포 경로와 보안 헤더
  http(2, 'root_page_nosniff', 'normal', 'GET', '/', '첫 화면이 열리고 X-Content-Type-Options: nosniff 헤더가 있음', [200], {
    headerIncludes: { 'x-content-type-options': 'nosniff' },
  }),
  http(2, 'aleph_json_public', 'normal', 'GET', '/aleph.json', '배포 식별 파일이 열림', [200]),
  hold(2, 'repo_exposure_search', 'forbidden', 'GET', '/data.json',
    '가상 메모 문구가 GitHub 최신 파일과 옛 커밋에 남아 있지 않음', null, 'not_run',
    'GitHub 파일·옛 커밋 검색은 HTTP 시험이 아니며 이번 실행에서 하지 않음'),

  // 3단계 — 로그인한 사용자만
  http(3, 'anonymous_notes_list_denied', 'forbidden', 'GET', '/api/notes',
    '로그인 없는 목록 조회는 401 UNAUTHORIZED로 거부', [401], { errorCode: 'UNAUTHORIZED', headerIncludes: NO_STORE }),

  // 4단계 — 내 메모만
  http(4, 'anonymous_note_by_id_denied', 'forbidden', 'GET', '/api/notes/:id',
    '로그인 없이 메모 ID로 조회하면 401 UNAUTHORIZED로 거부', [401], { errorCode: 'UNAUTHORIZED' }),
  hold(4, 'cross_user_note_read_denied', 'forbidden', 'GET', '/api/notes/:id',
    '다른 사용자의 메모 ID는 404 NOTE_NOT_FOUND로 거부', [404], 'not_run',
    '두 번째 시험 계정의 메모 ID와 두 계정의 로그인·기기 세션이 필요하며 이번 실행에서 제공되지 않음'),

  // 5단계 — 서버를 거치는 로그인. 잘못된 비밀번호 시도는 보내지 않는다(무차별 대입 탐지와 섞이지 않게).
  http(5, 'login_cross_origin_denied', 'forbidden', 'POST', '/api/auth/login',
    '다른 출처에서 온 로그인 요청은 403 INVALID_ORIGIN으로 거부', [403], { origin: 'foreign', body: {}, errorCode: 'INVALID_ORIGIN' }),
  http(5, 'login_empty_input_rejected', 'forbidden', 'POST', '/api/auth/login',
    '이메일·비밀번호가 없는 로그인 요청은 400 INVALID_LOGIN_INPUT으로 거부', [400], { origin: 'same', body: {}, errorCode: 'INVALID_LOGIN_INPUT' }),
  http(5, 'login_get_method_denied', 'forbidden', 'GET', '/api/auth/login',
    'GET 로그인 요청은 405 METHOD_NOT_ALLOWED로 거부', [405], { errorCode: 'METHOD_NOT_ALLOWED' }),

  // 6단계 — 등록한 기기만
  hold(6, 'registered_device_read_allowed', 'normal', 'GET', '/api/notes',
    '등록 기기의 정상 자료 조회는 허용(allow)', null, 'unverified', LOCAL_ONLY('npm run decider:test')),
  hold(6, 'unregistered_device_denied', 'forbidden', 'GET', '/api/notes',
    '미등록 기기의 요청은 거부(deny, device_not_registered)', null, 'unverified',
    '미등록 기기를 쓰는 실제 요청은 운영 심판이 수행하며 이 점검기가 HTTP로 만들 수 없음'),

  // 7단계 — 복합 이상 접속과 추가 확인
  hold(7, 'step_up_required_before_notes', 'forbidden', 'GET', '/api/notes',
    '복합 이상 접속에서는 추가 확인(step_up) 전 자료 요청이 차단됨', null, 'unverified',
    '재인증 전 요청의 서버 차단과 엔진의 재인증 검증은 HTTP 응답으로 확인하지 못함'),
  hold(7, 'notes_after_reauth_allowed', 'normal', 'GET', '/api/notes',
    '추가 확인을 마친 뒤의 자료 요청은 허용', null, 'unverified',
    '재인증 이후 요청이 판정 엔진에서 다시 평가되는지는 HTTP 응답으로 확인하지 못함'),

  // 8단계 — 자료 API의 사용자 권한
  http(8, 'anonymous_note_create_denied', 'forbidden', 'POST', '/api/notes',
    '로그인 없는 메모 생성은 401 UNAUTHORIZED로 거부', [401], { origin: 'same', body: {}, errorCode: 'UNAUTHORIZED' }),
  http(8, 'anonymous_note_delete_denied', 'forbidden', 'DELETE', '/api/notes/:id',
    '로그인 없는 메모 삭제는 401 UNAUTHORIZED로 거부', [401], { origin: 'same', errorCode: 'UNAUTHORIZED' }),
  http(8, 'cross_origin_note_create_denied', 'forbidden', 'POST', '/api/notes',
    '다른 출처의 메모 생성은 403 INVALID_ORIGIN으로 거부', [403], { origin: 'foreign', body: {}, errorCode: 'INVALID_ORIGIN' }),
  http(8, 'notes_patch_method_denied', 'forbidden', 'PATCH', '/api/notes',
    '허용되지 않은 PATCH는 405 METHOD_NOT_ALLOWED로 거부', [405], { origin: 'same', body: {}, errorCode: 'METHOD_NOT_ALLOWED' }),
  http(8, 'unknown_api_route_denied', 'forbidden', 'GET', '/api/notes-admin',
    '없는 API 경로는 404로 거부', [404]),
  hold(8, 'own_note_write_allowed', 'normal', 'POST', '/api/notes',
    '승인된 기기 세션의 본인 메모 생성은 201로 허용', [201], 'not_run',
    '메모를 만드는 요청이라 자동으로 보내지 않음'),

  // 9단계 — 폭주 조회 탐지
  hold(9, 'normal_read_observe_classified', 'normal', 'GET', '/api/notes',
    '정상 조회량은 observe로 분류', null, 'unverified', LOCAL_ONLY('npm run detect:test')),
  hold(9, 'burst_read_revocation_proposed', 'forbidden', 'GET', '/api/notes',
    '10분 이내 121건 이상의 폭주 조회는 propose_revocation으로 분류', null, 'not_run',
    '대량 요청이라 자동으로 보내지 않음'),

  // 10단계 — 메모 복구
  http(10, 'restore_get_method_denied', 'forbidden', 'GET', '/api/notes/:id/restore',
    'GET 복구 요청은 405 METHOD_NOT_ALLOWED로 거부', [405], { errorCode: 'METHOD_NOT_ALLOWED' }),
  http(10, 'anonymous_restore_denied', 'forbidden', 'POST', '/api/notes/:id/restore',
    '로그인 없는 복구 요청은 401 UNAUTHORIZED로 거부', [401], { origin: 'same', body: {}, errorCode: 'UNAUTHORIZED' }),
  http(10, 'cross_origin_restore_denied', 'forbidden', 'POST', '/api/notes/:id/restore',
    '다른 출처의 복구 요청은 403 INVALID_ORIGIN으로 거부', [403], { origin: 'foreign', body: {}, errorCode: 'INVALID_ORIGIN' }),
  hold(10, 'cross_user_restore_denied', 'forbidden', 'POST', '/api/notes/:id/restore',
    '다른 사용자의 메모 복구는 거부됨', null, 'not_run',
    '두 번째 시험 계정과 스냅샷이 필요하고 메모를 바꿀 수 있는 요청이라 자동으로 보내지 않음'),
  hold(10, 'own_note_restore_allowed', 'normal', 'POST', '/api/notes/:id/restore',
    '본인 메모 복구는 지정한 스냅샷·해시가 맞을 때 200으로 허용', [200], 'not_run',
    '스냅샷 ID·내용 해시·유효한 세션이 필요하고 메모를 바꾸는 요청이라 자동으로 보내지 않음'),

  // 11단계 — 승인된 기기에서만
  http(11, 'device_status_anonymous_denied', 'forbidden', 'POST', '/api/device/status',
    '로그인 없는 기기 상태 조회는 401 UNAUTHORIZED로 거부', [401],
    { origin: 'same', body: {}, errorCode: 'UNAUTHORIZED', headerIncludes: NO_STORE }),
  http(11, 'device_status_cross_origin_denied', 'forbidden', 'POST', '/api/device/status',
    '다른 출처의 기기 상태 조회는 403 INVALID_ORIGIN으로 거부', [403],
    { origin: 'foreign', body: {}, errorCode: 'INVALID_ORIGIN' }),
  http(11, 'device_status_get_method_denied', 'forbidden', 'GET', '/api/device/status',
    'GET 기기 상태 조회는 405 METHOD_NOT_ALLOWED로 거부하고 Allow: POST를 알림', [405],
    { errorCode: 'METHOD_NOT_ALLOWED', headerIncludes: { allow: 'POST' } }),
  http(11, 'device_register_options_anonymous_denied', 'forbidden', 'POST', '/api/device/register-options',
    '로그인 없는 기기 등록 옵션 요청은 401 UNAUTHORIZED로 거부', [401],
    { origin: 'same', body: {}, errorCode: 'UNAUTHORIZED' }),
  http(11, 'device_auth_verify_anonymous_denied', 'forbidden', 'POST', '/api/device/auth-verify',
    '로그인 없는 기기 인증 확인은 401 UNAUTHORIZED로 거부', [401],
    { origin: 'same', body: {}, errorCode: 'UNAUTHORIZED' }),
  // 쓰기 요청(POST)이라 보내지 않는다. 세션 확인은 아래 GET 사전 시험이 맡는다.
  http(11, 'device_status_session_valid', 'normal', 'POST', '/api/device/status',
    '승인된 기기 세션으로 기기 상태를 조회하면 200 session_valid', [200], {
      origin: 'same', body: {}, auth: 'both',
    }),
  // 사전 시험: 이 시험이 통과해야 아래 세션 필요 시험을 보낸다.
  http(11, 'notes_list_with_device_session', 'normal', 'GET', '/api/notes',
    '승인된 기기 세션의 본인 메모 목록 조회는 200으로 허용', [200], {
      auth: 'both', role: 'precheck',
      verify: ({ json, ctx }) => {
        if (!Array.isArray(json)) return '응답이 메모 목록 배열이 아님';
        // 다음 시험이 쓸 메모 ID만 기억한다. 제목·본문은 읽지도 기록하지도 않는다.
        const id = json[0]?.id;
        ctx.firstNoteId = typeof id === 'string' && UUID.test(id) ? id : null;
        return true;
      },
    }),
  http(11, 'notes_login_without_device_session_denied', 'forbidden', 'GET', '/api/notes',
    '로그인만 있고 기기 세션이 없으면 403 DEVICE_APPROVAL_REQUIRED로 거부', [403],
    { auth: 'login', needs: 'session', errorCode: 'DEVICE_APPROVAL_REQUIRED' }),
  http(11, 'own_note_read_with_device_session', 'normal', 'GET', '/api/notes/:id',
    '승인된 기기 세션의 본인 메모 단건 조회는 200으로 허용', [200], {
      auth: 'both', needs: 'session', useFirstNote: true,
      verify: ({ json, ctx }) => json?.id === ctx.firstNoteId || '응답의 메모 ID가 요청한 ID와 다름',
    }),
]);

function readAppUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  return app;
}

function readSession(env) {
  const login = typeof env?.[ATTACK_ENV.login] === 'string' ? env[ATTACK_ENV.login].trim() : '';
  const device = typeof env?.[ATTACK_ENV.device] === 'string' ? env[ATTACK_ENV.device].trim() : '';
  if (!login || !device) return { state: 'missing' };
  if (login.length > 4096 || !LOGIN_TOKEN.test(login) || !DEVICE_TOKEN.test(device)) return { state: 'malformed' };
  return { state: 'unchecked', login, device };
}

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

function unsent(def, status, reason) {
  return {
    stage: def.stage, testId: def.testId, kind: def.kind, method: def.method, path: def.path,
    expected: def.expected, expectedStatus: def.expectedStatus ? [...def.expectedStatus] : null,
    status, httpStatus: null, errorCode: null, headers: null, requestId: null, requestIdSource: null,
    checkedAt: null, observed: null, reason,
  };
}

function sessionBlock(def, ctx) {
  const { state } = ctx.session;
  if (def.role === 'precheck' ? state === 'unchecked' : state === 'valid') return null;
  if (state === 'missing') {
    return `유효한 로그인·기기 세션을 확보하지 못함: 시험용 세션 값(${ATTACK_ENV.login}, ${ATTACK_ENV.device})이 없어 보내지 않음`;
  }
  if (state === 'malformed') return '시험용 세션 값의 형식이 맞지 않아 보내지 않음';
  return '유효한 기기 세션을 확보하지 못함: 사전 시험 notes_list_with_device_session이 통과하지 못해 보내지 않음';
}

function cleanHeader(value) {
  return String(value).replace(/[\u0000-\u001f\u007f]/gu, ' ').trim().slice(0, 200);
}

function pickHeaders(headers) {
  const picked = {};
  for (const name of RECORDABLE_HEADERS) {
    const value = headers?.get?.(name);
    const clean = typeof value === 'string' ? cleanHeader(value) : '';
    if (clean) picked[name] = clean;
  }
  return picked;
}

// 응답 헤더에 실제로 있는 요청 ID만 읽는다. 없으면 null이며, 어떤 값도 만들어 넣지 않는다.
function pickRequestId(headers) {
  for (const name of REQUEST_ID_HEADERS) {
    const value = headers?.get?.(name);
    if (typeof value === 'string' && REQUEST_ID_PATTERN.test(value.trim())) {
      return { requestId: value.trim(), requestIdSource: name };
    }
  }
  return { requestId: null, requestIdSource: null };
}

async function readJson(response) {
  try {
    const text = await response.text();
    if (text.length > 200000 || !/^\s*[[{]/u.test(text)) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function execute(def, ctx) {
  const requestPath = def.path.replace(':id', def.useFirstNote ? ctx.firstNoteId : PLACEHOLDER_NOTE_ID);
  const headers = {};
  if (def.origin === 'same') headers.origin = ctx.app.origin;
  if (def.origin === 'foreign') headers.origin = FOREIGN_ORIGIN;
  let body;
  if (def.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(def.body);
  }
  if (def.auth !== 'none') {
    const cookies = [`${LOGIN_COOKIE}=${ctx.session.login}`];
    if (def.auth === 'both') cookies.push(`${DEVICE_COOKIE}=${ctx.session.device}`);
    headers.cookie = cookies.join('; ');
  }

  const checkedAt = ctx.now().toISOString();
  let response;
  try {
    response = await ctx.fetch(new URL(requestPath, ctx.app), {
      method: def.method, headers, body, redirect: 'error', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    // 요청은 보냈지만 응답이 없다. 거부된 것으로도, 허용된 것으로도 세지 않고 실패로 남긴다.
    const kind = typeof error?.name === 'string' && /^[A-Za-z]{1,40}$/u.test(error.name) ? error.name : 'Error';
    return {
      ...unsent(def, 'fail', '요청은 보냈으나 HTTP 응답을 받지 못해 기대 결과를 확인하지 못함'),
      expectedStatus: [...def.expectedStatus], checkedAt, observed: `응답을 받지 못함 (${kind})`,
    };
  }

  const httpStatus = response.status;
  const recorded = pickHeaders(response.headers);
  const { requestId, requestIdSource } = pickRequestId(response.headers);
  const json = await readJson(response);
  const code = typeof json?.error === 'string' && ERROR_CODE_PATTERN.test(json.error) ? json.error : null;

  const problems = [];
  if (!def.expectedStatus.includes(httpStatus)) {
    problems.push(`상태 ${httpStatus}이(가) 기대 상태 ${def.expectedStatus.join('·')}와 다름`);
  }
  if (def.errorCode && code !== def.errorCode) problems.push(`오류 코드가 기대한 ${def.errorCode}와 다름`);
  for (const [name, needle] of Object.entries(def.headerIncludes ?? {})) {
    if (!(recorded[name] ?? '').toLowerCase().includes(needle.toLowerCase())) {
      problems.push(`응답 헤더 ${name}에 ${needle}이(가) 없음`);
    }
  }
  if (!problems.length && def.verify) {
    const outcome = def.verify({ json, ctx });
    if (outcome !== true) problems.push(typeof outcome === 'string' ? outcome : '응답 내용이 기대와 다름');
  }
  const ok = problems.length === 0;

  let observed;
  if (def.summarize) {
    observed = def.summarize(ok, httpStatus);
  } else {
    const facts = [`HTTP ${httpStatus}`];
    if (code) facts.push(code);
    for (const name of ['cache-control', 'x-content-type-options', 'allow']) {
      if (recorded[name]) facts.push(`${name}: ${recorded[name]}`);
    }
    observed = facts.join(' · ');
  }
  let reason = ok ? null : problems.join('; ');
  if (!ok && def.role === 'precheck') {
    reason += '. 이 시험이 통과하지 못하면 세션이 필요한 나머지 시험은 보내지 않고 not_run으로 남김';
  }

  return {
    stage: def.stage, testId: def.testId, kind: def.kind, method: def.method, path: def.path,
    expected: def.expected, expectedStatus: [...def.expectedStatus],
    status: ok ? 'pass' : 'fail', httpStatus, errorCode: code, headers: recorded,
    requestId, requestIdSource, checkedAt,
    observed: observed.slice(0, 300), reason: reason === null ? null : reason.slice(0, 300),
  };
}

async function runOne(def, ctx) {
  if (def.type === 'hold') return unsent(def, def.status, def.reason);
  // 쓰기 요청이 필요한 시험은 보내지 않는다. 응답·요청 ID·시각은 모두 null로 남는다.
  if (!SENDABLE_METHODS.includes(def.method)) {
    return unsent(def, 'not_run', `${def.method} 요청은 이 점검기가 보내지 않음(GET·HEAD만 보냄): 쓰기 요청 점검은 미실행`);
  }
  if (def.needs === 'session' || def.role === 'precheck') {
    const blocked = sessionBlock(def, ctx);
    if (blocked) return unsent(def, 'not_run', blocked);
  }
  if (def.useFirstNote && !ctx.firstNoteId) return unsent(def, 'not_run', '조회할 본인 메모 ID가 없어 보내지 않음');
  if (ctx.sent >= ctx.maxRequests) {
    return unsent(def, 'not_run', `이번 실행의 요청 수 상한(${ctx.maxRequests}건)에 도달해 보내지 않음`);
  }
  if (ctx.sent > 0 && ctx.delayMs > 0) await sleep(ctx.delayMs);
  ctx.sent += 1;
  const record = await execute(def, ctx);
  if (def.role === 'precheck') ctx.session.state = record.status === 'pass' ? 'valid' : 'invalid';
  return record;
}

// options는 시험과 점검용: fetch, now, env, delayMs, maxRequests
export async function runAttackChecks(config, options = {}) {
  const app = readAppUrl(config);
  const doFetch = options.fetch ?? globalThis.fetch;
  if (typeof doFetch !== 'function') throw new Error('이 환경에서는 HTTP 요청을 보낼 수 없습니다.');
  const ctx = {
    app, marker: config.sampleMarker, fetch: doFetch, now: options.now ?? (() => new Date()),
    delayMs: options.delayMs ?? DEFAULT_DELAY_MS, maxRequests: options.maxRequests ?? DEFAULT_MAX_REQUESTS,
    sent: 0, session: readSession(options.env ?? process.env), firstNoteId: null,
  };
  const records = [];
  for (const def of CATALOG) records.push(await runOne(def, ctx));
  // 점검기가 스스로 만든 기록이 계약을 어기면 번들까지 가기 전에 여기서 멈춘다.
  return validateAttackRecords(records);
}
