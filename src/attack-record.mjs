// 시험 기록표의 형식과 검증. src/attack-check.mjs(기록을 만든다)와
// scripts/bundle.mjs(제출 전에 검사한다)가 같은 계약을 쓰도록 한 곳에 둔다.
//
// 한 기록 = 시험 한 건. 열여섯 개 이름만 허용한다.
//
//   stage            1~12  단계 번호
//   testId           영문·숫자·_ . - (기록표 안에서 유일)
//   kind             'normal'(허용되어야 함) | 'forbidden'(거부되어야 함)
//   method, path     GET/POST/PUT/PATCH/DELETE 와 경로 모양(예: /api/notes/:id). 쿼리·실제 ID는 넣지 않는다.
//   expected         기대 결과 설명
//   expectedStatus   기대하는 HTTP 상태 코드 배열. HTTP로 정할 수 없는 항목은 null (미실측 기록만 가능)
//   status           'pass' | 'fail' | 'not_run' | 'unverified'
//   httpStatus       실제 응답 상태 코드. 응답을 받지 못했거나 보내지 않았으면 null
//   errorCode        응답 JSON의 error 코드(예: UNAUTHORIZED). 없으면 null
//   headers          확인한 응답 헤더(허용 목록만). 응답이 없으면 null
//   requestId        응답 헤더에서 읽은 요청 ID. 응답에 없으면 null — 만들어 넣지 않는다
//   requestIdSource  requestId를 읽은 헤더 이름. requestId가 null이면 null
//   checkedAt        요청을 실행한 시각(ISO 8601, UTC). 보내지 않았으면 null
//   observed         실제로 관찰한 내용 한 줄. 보내지 않았으면 null
//   reason           fail의 불일치 이유, not_run/unverified의 사유
//
// 상태의 뜻:
//   pass       요청을 보냈고 응답이 기대와 모두 맞았다.
//   fail       요청을 보냈지만 기대와 달랐다. 응답을 받지 못한 경우(시간 초과 등)도 여기에 속하며 httpStatus가 null이다.
//   not_run    이 점검기가 보낼 수 있는 요청이지만 이번 실행에서 보내지 않았다
//              (시험용 세션 없음, 다른 계정 필요, 메모를 바꾸는 요청, 대량 요청 등).
//   unverified HTTP 요청만으로는 확인할 수 없는 항목(로컬 가상 시험, 운영 엔진·심판 쪽 판정).
//              과거 기록이 있어도 이번에 실제 응답으로 확인하지 않았다.
// not_run과 unverified는 요청을 보내지 않았다는 뜻이므로 응답 값·요청 ID·시각을 모두 null로 둔다.
// 이 둘은 성공으로 세지 않는다. 비밀값·인증 토큰·쿠키·메모 본문은 어느 필드에도 넣지 않는다.

export const MAX_ATTACK_RECORDS = 60;
export const MAX_STAGE = 12;
export const ATTACK_KINDS = Object.freeze(['normal', 'forbidden']);
export const ATTACK_STATUSES = Object.freeze(['pass', 'fail', 'not_run', 'unverified']);
export const ATTACK_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
// 기록할 수 있는 응답 헤더. set-cookie·authorization 같은 헤더는 목록에 없으므로 기록되지 않는다.
export const RECORDABLE_HEADERS = Object.freeze([
  'allow', 'cache-control', 'content-type', 'x-content-type-options',
]);
export const REQUEST_ID_HEADERS = Object.freeze(['x-vercel-id', 'x-request-id']);

const RECORD_KEYS = [
  'checkedAt', 'errorCode', 'expected', 'expectedStatus', 'headers', 'httpStatus', 'kind',
  'method', 'observed', 'path', 'reason', 'requestId', 'requestIdSource', 'stage', 'status',
  'testId',
];
const TEST_ID = /^[a-z0-9][a-z0-9_.-]{0,79}$/iu;
const PATH = /^\/[A-Za-z0-9._~:/-]{0,199}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
export const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{2,63}$/u;
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/u;
// 쿠키·토큰·개인키처럼 보이는 문자열은 어느 문자열 필드에도 들어올 수 없다.
const SECRET_TEXT = /-----BEGIN|__Host-[A-Za-z0-9-]+=|set-cookie|\beyJ[A-Za-z0-9_-]{8,}|sb_secret_|\bsk-[A-Za-z0-9_-]{16,}/iu;

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isText = (value, max) => typeof value === 'string' && value.trim() !== '' && value.length <= max;
const isHttpStatus = (value) => Number.isInteger(value) && value >= 100 && value <= 599;
const isStatusList = (value) => Array.isArray(value) && value.length >= 1 && value.length <= 4
  && value.every(isHttpStatus) && new Set(value).size === value.length;
const isIsoTime = (value) => typeof value === 'string' && ISO_UTC.test(value)
  && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value
  // 아직 오지 않은 시각은 실제로 요청을 실행한 시각일 수 없다.
  && Date.parse(value) <= Date.now() + 5 * 60 * 1000;

function check(label, condition, message) {
  if (!condition) throw new Error(`시험 기록 ${label}: ${message}`);
}

function checkRecord(record, label) {
  check(label, isObject(record), '기록은 객체여야 합니다.');
  check(label, Object.keys(record).sort().join(',') === RECORD_KEYS.join(','),
    `필드는 ${RECORD_KEYS.join('·')}만 넣어 주세요.`);
  check(label, Number.isInteger(record.stage) && record.stage >= 1 && record.stage <= MAX_STAGE,
    `stage는 1~${MAX_STAGE}의 정수여야 합니다.`);
  check(label, typeof record.testId === 'string' && TEST_ID.test(record.testId), 'testId 형식을 확인해 주세요.');
  check(label, ATTACK_KINDS.includes(record.kind), "kind는 'normal' 또는 'forbidden'이어야 합니다.");
  check(label, ATTACK_METHODS.includes(record.method), 'method는 GET·POST·PUT·PATCH·DELETE 중 하나여야 합니다.');
  check(label, typeof record.path === 'string' && PATH.test(record.path),
    'path는 /로 시작하는 경로 모양이어야 하며 쿼리를 넣을 수 없습니다.');
  check(label, isText(record.expected, 300), 'expected에 기대 결과를 300자 이내로 적어 주세요.');
  check(label, ATTACK_STATUSES.includes(record.status), 'status는 pass·fail·not_run·unverified 중 하나여야 합니다.');
  check(label, record.expectedStatus === null || isStatusList(record.expectedStatus),
    'expectedStatus는 100~599의 서로 다른 상태 코드 1~4개 또는 null이어야 합니다.');

  const sent = record.status === 'pass' || record.status === 'fail';
  if (!sent) {
    // 보내지 않은 시험에는 응답처럼 보이는 값이 하나도 있으면 안 된다.
    for (const key of ['httpStatus', 'errorCode', 'headers', 'requestId', 'requestIdSource', 'checkedAt', 'observed']) {
      check(label, record[key] === null, `${record.status} 기록의 ${key}는 null이어야 합니다. 보내지 않은 시험에 응답 값을 넣을 수 없습니다.`);
    }
    check(label, isText(record.reason, 300), `${record.status} 기록에는 사유(reason)가 필요합니다.`);
    return;
  }

  check(label, isStatusList(record.expectedStatus), '실측 기록에는 expectedStatus가 필요합니다.');
  check(label, isIsoTime(record.checkedAt), 'checkedAt은 요청을 실행한 시각의 ISO 8601(UTC, 밀리초 포함) 값이어야 합니다.');
  check(label, isText(record.observed, 300), '실측 기록에는 observed가 필요합니다.');
  check(label, record.reason === null || isText(record.reason, 300), 'reason은 300자 이내 문자열 또는 null이어야 합니다.');

  if (record.httpStatus === null) {
    // 요청은 보냈지만 응답을 받지 못한 경우. 성공일 수 없고 응답에서 온 값도 없다.
    check(label, record.status === 'fail', '응답을 받지 못한 시험은 fail이어야 합니다.');
    for (const key of ['errorCode', 'headers', 'requestId', 'requestIdSource']) {
      check(label, record[key] === null, `응답이 없는 기록의 ${key}는 null이어야 합니다.`);
    }
  } else {
    check(label, isHttpStatus(record.httpStatus), 'httpStatus는 100~599의 정수여야 합니다.');
    const matches = record.expectedStatus.includes(record.httpStatus);
    check(label, record.status !== 'pass' || matches,
      `httpStatus ${record.httpStatus}는 기대 상태 ${record.expectedStatus.join('·')}에 없으므로 pass일 수 없습니다.`);
    check(label, record.errorCode === null || (typeof record.errorCode === 'string' && ERROR_CODE_PATTERN.test(record.errorCode)),
      'errorCode 형식을 확인해 주세요.');
    check(label, isObject(record.headers), '응답을 받은 기록의 headers는 객체여야 합니다.');
    for (const [name, value] of Object.entries(record.headers)) {
      check(label, RECORDABLE_HEADERS.includes(name) && typeof value === 'string' && value.length <= 200,
        `headers에는 ${RECORDABLE_HEADERS.join('·')}만 200자 이내로 넣을 수 있습니다.`);
    }
    if (record.requestId === null) {
      check(label, record.requestIdSource === null, 'requestId가 null이면 requestIdSource도 null이어야 합니다.');
    } else {
      check(label, typeof record.requestId === 'string' && REQUEST_ID_PATTERN.test(record.requestId)
        && REQUEST_ID_HEADERS.includes(record.requestIdSource),
      'requestId는 응답의 x-vercel-id 또는 x-request-id 헤더에서 읽은 값이어야 합니다.');
    }
  }
  check(label, record.status !== 'fail' || isText(record.reason, 300), 'fail 기록에는 사유(reason)가 필요합니다.');
}

// 기록표 전체를 검사한다. 문제가 있으면 첫 문제를 한국어 메시지로 던진다.
export function validateAttackRecords(records) {
  if (!Array.isArray(records) || records.length < 1 || records.length > MAX_ATTACK_RECORDS) {
    throw new Error(`직접 실행한 시험 기록 1~${MAX_ATTACK_RECORDS}개가 필요합니다.`);
  }
  const seen = new Set();
  records.forEach((record, index) => {
    const label = `#${index + 1}${isObject(record) && typeof record.testId === 'string' ? `(${record.testId.slice(0, 80)})` : ''}`;
    checkRecord(record, label);
    check(label, !seen.has(record.testId), 'testId가 중복되었습니다.');
    seen.add(record.testId);
    for (const value of Object.values(record)) {
      const strings = isObject(value) ? Object.values(value) : [value];
      check(label, !strings.some(item => typeof item === 'string' && SECRET_TEXT.test(item)),
        '비밀값·쿠키·토큰으로 보이는 내용이 있습니다.');
    }
  });
  return records;
}

// 상태별 개수. 성공은 pass만 센다. not_run과 unverified는 실측이 아니므로 measured에도 들어가지 않는다.
export function summarizeAttackRecords(records) {
  const summary = { total: records.length, pass: 0, fail: 0, not_run: 0, unverified: 0 };
  for (const record of records) summary[record.status] += 1;
  return { ...summary, measured: summary.pass + summary.fail };
}

// ---- 채점표 형식(attackAttempts) ----
// 제출 묶음 `aleph.defense.submission.v2`의 attackAttempts는 { attackId, expected, observed } 세 필드만 가진다.
// 시험 기록표의 기록을 이 모양으로 바꾼다. 실제로 받은 HTTP 상태가 있을 때만 상태 코드 숫자만(예: '401')을 observed에 적고,
// 그 밖에는 모두 'not_run'으로 둔다: 보내지 않은 시험(not_run·unverified)과, 요청은 시도했으나
// HTTP 응답을 받지 못해 확인된 상태가 없는 시험이다. 어떤 값도 만들어 넣지 않는다.
// (응답을 받지 못한 시험은 시험 기록표에서는 fail, 점검 결과 파일에서는 httpStatus null로 그대로 남는다.)
export const MAX_SUBMISSION_ATTEMPTS = 20;

// 심판 메모에서 "요청 기록이 없다"고 지적된 시험. 점검기는 요청을 보내고 응답을 받았지만, 심판이 해당 ID의
// 요청 기록을 확인하지 못했으므로 제출 기록(attackAttempts)에서는 확인된 결과가 없는 것으로 not_run을 적는다.
// 시험 기록표와 public/attack-results.json에는 실제로 받은 응답이 그대로 남는다. 새 메모가 오면 이 목록만 고친다.
export const SENT_BUT_UNCONFIRMED = Object.freeze([
  'anonymous_note_read', 'root_page_nosniff', 'aleph_json_public',
  'anonymous_notes_list_denied', 'anonymous_note_by_id_denied', 'login_get_method_denied',
]);

export function toAttackAttempt(record) {
  let observed = 'not_run';
  if ((record.status === 'pass' || record.status === 'fail') && Number.isInteger(record.httpStatus)
      && !SENT_BUT_UNCONFIRMED.includes(record.testId)) {
    observed = String(record.httpStatus);
  }
  return { attackId: record.testId, expected: record.expected, observed };
}

// 채점표는 한 묶음에 최대 20개를 받는다. 기록이 더 많으면 아래 순서로 자리를 채우고, 고른 뒤에는 표 순서로 되돌린다.
//   1) 실제로 요청을 보낸 시험 전부
//   2) 보낸 시험이 하나도 없는 단계(6·7·9단계 등)의 시험 전부 — 어느 단계도 제출 기록에서 빠지지 않게
//   3) 보내지 않은 정상(normal) 시험 — 금지 요청 거부와 정상 요청 허용이 둘 다 기록에 남게
//   4) 나머지(쓰기 요청이라 보내지 않은 시험이 먼저, 그다음 읽기 시험)
// 어느 경우에도 보내지 않은 시험의 observed는 not_run이고, 순서는 결과를 바꾸지 않는다.
export function toAttackAttempts(records, max = MAX_SUBMISSION_ATTEMPTS) {
  const sent = (record) => record.status === 'pass' || record.status === 'fail';
  const sentStages = new Set(records.filter(sent).map((record) => record.stage));
  const rank = (record) => {
    if (sent(record)) return 0;
    if (!sentStages.has(record.stage)) return 1;
    if (record.kind === 'normal') return 2;
    return ATTACK_READ_METHODS.includes(record.method) ? 4 : 3;
  };
  const chosen = records
    .map((record, index) => ({ record, index }))
    .sort((a, b) => rank(a.record) - rank(b.record) || a.index - b.index)
    .slice(0, max)
    .sort((a, b) => a.index - b.index);
  return chosen.map(({ record }) => toAttackAttempt(record));
}
const ATTACK_READ_METHODS = Object.freeze(['GET', 'HEAD']);

// 채점표 형식 검사: 세 필드만, ID는 유일, 글자 수 제한.
export function validateAttackAttempts(attempts, max = MAX_SUBMISSION_ATTEMPTS) {
  if (!Array.isArray(attempts) || !attempts.length || attempts.length > max) {
    throw new Error(`직접 실행한 공격 점검 결과 1~${max}개가 필요합니다.`);
  }
  for (const attempt of attempts) {
    if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt)
        || Object.keys(attempt).sort().join(',') !== 'attackId,expected,observed'
        || typeof attempt.attackId !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,79}$/iu.test(attempt.attackId)
        || typeof attempt.expected !== 'string' || !attempt.expected.trim() || attempt.expected.length > 300
        || typeof attempt.observed !== 'string' || !attempt.observed.trim() || attempt.observed.length > 300) {
      throw new Error('공격 점검 결과에는 attackId·expected·observed만 넣어 주세요.');
    }
  }
  if (new Set(attempts.map(item => item.attackId)).size !== attempts.length) throw new Error('공격 점검 ID가 중복되었습니다.');
  return attempts;
}
