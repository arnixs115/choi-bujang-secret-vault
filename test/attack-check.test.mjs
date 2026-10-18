// 시험 기록표(src/attack-check.mjs, src/attack-record.mjs, scripts/bundle.mjs) 시험.
// 모든 HTTP 응답은 test/helpers/fake-deployment.mjs 의 가상 응답이다. 실제 배포로 요청을 보내지 않으며,
// 이 시험이 통과해도 실제 배포나 운영 심판의 결과를 확인한 것이 아니다.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ATTACK_ENV, runAttackChecks } from '../src/attack-check.mjs';
import {
  summarizeAttackRecords, toAttackAttempt, toAttackAttempts, validateAttackAttempts, validateAttackRecords,
} from '../src/attack-record.mjs';
import { pathToFileURL } from 'node:url';
import {
  SAMPLE_MARKER, SECRET_NOTE_BODY, SECRET_NOTE_ID, SECRET_NOTE_TITLE, SECRET_SET_COOKIE,
  TEST_DEVICE_TOKEN, TEST_LOGIN_TOKEN, VERCEL_ID, createFakeDeployment,
} from './helpers/fake-deployment.mjs';

const root = join(import.meta.dirname, '..');
const config = {
  step: 11,
  publicAppUrl: 'https://student-defense.vercel.app/',
  sampleMarker: SAMPLE_MARKER,
};
const SESSION_ENV = { [ATTACK_ENV.login]: TEST_LOGIN_TOKEN, [ATTACK_ENV.device]: TEST_DEVICE_TOKEN };
const RESPONSE_FIELDS = ['httpStatus', 'errorCode', 'headers', 'requestId', 'requestIdSource', 'checkedAt', 'observed'];

async function run(deployment, options = {}) {
  const records = await runAttackChecks(config, {
    fetch: deployment.fetch, delayMs: 0, env: {}, ...options,
  });
  return new Map(records.map(record => [record.testId, record]));
}
const sentCount = (byId) => [...byId.values()].filter(r => r.status === 'pass' || r.status === 'fail').length;
const fakeRecord = (overrides = {}) => ({
  stage: 3, testId: 'sample_test', kind: 'forbidden', method: 'GET', path: '/api/notes',
  expected: '거부', expectedStatus: [401], status: 'pass', httpStatus: 401, errorCode: 'UNAUTHORIZED',
  headers: { 'cache-control': 'no-store' }, requestId: null, requestIdSource: null,
  checkedAt: new Date(Date.now() - 1000).toISOString(), observed: 'HTTP 401', reason: null, ...overrides,
});
const unsentRecord = (overrides = {}) => fakeRecord({
  status: 'not_run', httpStatus: null, errorCode: null, headers: null, requestId: null, requestIdSource: null,
  checkedAt: null, observed: null, reason: '보내지 않음', ...overrides,
});

test('점검 파일은 서버 코드를 가져오지 않고 쿠키 이름은 서버 상수와 같다', async () => {
  const source = readFileSync(join(root, 'src', 'attack-check.mjs'), 'utf8');
  assert.doesNotMatch(source, /from\s+['"][^'"]*device-session/u);
  const { DEVICE_COOKIE } = await import('../src/device-session.mjs');
  assert.ok(source.includes(`const DEVICE_COOKIE = '${DEVICE_COOKIE}';`));
});

test('금지 요청이 실제로 거부된 응답은 측정 결과(pass)로 기록된다', async () => {
  const deployment = createFakeDeployment();
  const byId = await run(deployment);
  const denied = byId.get('anonymous_notes_list_denied');
  assert.equal(denied.kind, 'forbidden');
  assert.equal(denied.method, 'GET');
  assert.equal(denied.path, '/api/notes');
  assert.equal(denied.status, 'pass');
  assert.equal(denied.httpStatus, 401);
  assert.equal(denied.errorCode, 'UNAUTHORIZED');
  assert.equal(denied.headers['cache-control'], 'no-store');
  assert.deepEqual(denied.expectedStatus, [401]);
  // 잘못된 메서드(GET)로 쓰기 전용 경로를 부른 거부도 상태와 헤더가 기록된다.
  assert.equal(byId.get('device_status_get_method_denied').headers.allow, 'POST');
  assert.equal(byId.get('device_status_get_method_denied').status, 'pass');
  assert.equal(byId.get('login_get_method_denied').httpStatus, 405);
  assert.equal(byId.get('restore_get_method_denied').httpStatus, 405);
});

test('정상 요청이 실제로 허용된 응답은 측정 결과(pass)로 기록된다', async () => {
  const deployment = createFakeDeployment();
  const byId = await run(deployment, { env: SESSION_ENV });
  for (const id of ['anonymous_note_read', 'root_page_nosniff', 'notes_list_with_device_session',
    'own_note_read_with_device_session']) {
    const record = byId.get(id);
    assert.equal(record.kind, 'normal', id);
    assert.equal(record.status, 'pass', id);
    assert.equal(record.httpStatus, 200, id);
  }
  // 로그인만 있고 기기 세션이 없으면 거부되는 금지 요청도 실제 응답으로 확인한다.
  const noDevice = byId.get('notes_login_without_device_session_denied');
  assert.equal(noDevice.status, 'pass');
  assert.equal(noDevice.httpStatus, 403);
  assert.equal(noDevice.errorCode, 'DEVICE_APPROVAL_REQUIRED');
  // 세션 값은 쿠키 요청 헤더로만 나갔다.
  const withCookie = deployment.calls.filter(call => call.headers.cookie);
  assert.equal(withCookie.length, 3); // 사전 시험, 로그인만 있는 거부 시험, 단건 조회
  assert.ok(withCookie.every(call => call.url.includes('/api/')));
});

test('GET·HEAD만 보내고 쓰기 요청이 필요한 시험은 보내지 않고 미실행으로 남긴다', async () => {
  const deployment = createFakeDeployment();
  const byId = await run(deployment, { env: SESSION_ENV });
  assert.ok(deployment.calls.length > 0);
  assert.ok(deployment.calls.every(call => ['GET', 'HEAD'].includes(call.method)),
    '쓰기 메서드로 요청을 보냄');
  assert.ok(deployment.calls.every(call => call.headers.origin === undefined), 'Origin을 꾸미는 요청을 보냄');
  const writes = ['login_cross_origin_denied', 'login_empty_input_rejected', 'anonymous_note_create_denied',
    'anonymous_note_delete_denied', 'cross_origin_note_create_denied', 'notes_patch_method_denied',
    'anonymous_restore_denied', 'cross_origin_restore_denied', 'device_status_anonymous_denied',
    'device_status_cross_origin_denied', 'device_register_options_anonymous_denied',
    'device_auth_verify_anonymous_denied', 'device_status_session_valid', 'own_note_write_allowed',
    'cross_user_restore_denied', 'own_note_restore_allowed'];
  for (const id of writes) {
    const record = byId.get(id);
    assert.ok(record, id);
    assert.ok(!['GET', 'HEAD'].includes(record.method), id);
    assert.equal(record.status, 'not_run', id);
    for (const field of RESPONSE_FIELDS) assert.equal(record[field], null, `${id}.${field}`);
  }
  // 시험표의 쓰기 요청 시험은 모두 미실행이고, 실측 기록은 모두 GET·HEAD다.
  for (const record of byId.values()) {
    if (record.status === 'pass' || record.status === 'fail') assert.ok(['GET', 'HEAD'].includes(record.method), record.testId);
  }
});

test('유효한 세션을 확보하지 못하면 세션이 필요한 정상 요청은 성공으로 기록되지 않는다', async () => {
  // 1) 세션 값이 없다.
  const none = createFakeDeployment();
  const missing = await run(none, { env: {} });
  const needsSession = ['notes_list_with_device_session', 'notes_login_without_device_session_denied',
    'own_note_read_with_device_session'];
  for (const id of needsSession) {
    assert.equal(missing.get(id).status, 'not_run', id);
    assert.match(missing.get(id).reason, /세션/u);
  }
  assert.equal(none.calls.some(call => call.headers.cookie), false);

  // 2) 세션 값은 있지만 서버가 기기 세션을 승인하지 않는다 → 사전 시험이 fail, 나머지는 보내지 않는다.
  const rejecting = createFakeDeployment({ deviceSessionValid: false });
  const invalid = await run(rejecting, { env: SESSION_ENV });
  assert.equal(invalid.get('notes_list_with_device_session').status, 'fail');
  assert.equal(invalid.get('notes_list_with_device_session').httpStatus, 403);
  assert.equal(invalid.get('notes_list_with_device_session').errorCode, 'DEVICE_APPROVAL_REQUIRED');
  for (const id of needsSession.slice(1)) {
    assert.equal(invalid.get(id).status, 'not_run', id);
    assert.match(invalid.get(id).reason, /기기 세션을 확보하지 못함/u);
  }
  assert.equal(rejecting.calls.filter(call => call.headers.cookie).length, 1);

  // 3) 형식이 맞지 않는 값은 보내지 않는다.
  const bad = createFakeDeployment();
  const malformed = await run(bad, { env: { [ATTACK_ENV.login]: 'not a token', [ATTACK_ENV.device]: 'x' } });
  assert.equal(malformed.get('notes_list_with_device_session').status, 'not_run');
  assert.equal(bad.calls.some(call => call.headers.cookie), false);
});

test('요청 ID는 응답 헤더에 있을 때만 기록하고 없으면 null이다', async () => {
  const withId = await run(createFakeDeployment({ requestId: true }));
  const sentWith = [...withId.values()].filter(r => r.httpStatus !== null);
  assert.equal(sentWith.length, 9);
  assert.ok(sentWith.every(r => r.requestId === VERCEL_ID && r.requestIdSource === 'x-vercel-id'));

  const withoutId = await run(createFakeDeployment({ requestId: false }));
  const sentWithout = [...withoutId.values()].filter(r => r.httpStatus !== null);
  assert.equal(sentWithout.length, 9);
  assert.ok(sentWithout.every(r => r.requestId === null && r.requestIdSource === null));
  // 보내지 않은 시험에는 어느 쪽에서도 요청 ID가 없다.
  for (const r of [...withId.values(), ...withoutId.values()]) {
    if (r.status === 'not_run' || r.status === 'unverified') assert.equal(r.requestId, null);
  }
  // 요청 ID처럼 보이지 않는 헤더 값은 버린다.
  const odd = await run(createFakeDeployment({ requestId: false, overrides: {
    'GET /api/notes': () => new Response('{"error":"UNAUTHORIZED"}', {
      status: 401, headers: { 'x-request-id': 'bad id with spaces', 'content-type': 'application/json' } }),
  } }));
  assert.equal(odd.get('anonymous_notes_list_denied').requestId, null);
});

test('실행하지 않은 시험은 미실행·미확인으로 남고 응답 값이 없다', async () => {
  const byId = await run(createFakeDeployment());
  const held = {
    repo_exposure_search: 'not_run', cross_user_note_read_denied: 'not_run',
    registered_device_read_allowed: 'unverified', unregistered_device_denied: 'unverified',
    step_up_required_before_notes: 'unverified', notes_after_reauth_allowed: 'unverified',
    own_note_write_allowed: 'not_run', normal_read_observe_classified: 'unverified',
    burst_read_revocation_proposed: 'not_run', cross_user_restore_denied: 'not_run',
    own_note_restore_allowed: 'not_run',
  };
  for (const [id, status] of Object.entries(held)) {
    const record = byId.get(id);
    assert.equal(record.status, status, id);
    for (const field of RESPONSE_FIELDS) assert.equal(record[field], null, `${id}.${field}`);
    assert.ok(record.reason.length > 0, id);
  }
  // 로컬 가상 시험이 따로 있어도 실행하지 않았으므로 pass로 올리지 않는다.
  assert.ok([...byId.values()].filter(r => r.status === 'pass').every(r => r.httpStatus !== null));
  const summary = summarizeAttackRecords([...byId.values()]);
  assert.equal(summary.total, byId.size);
  assert.equal(summary.pass + summary.fail, summary.measured);
  assert.equal(summary.measured, sentCount(byId));
  assert.ok(summary.not_run > 0 && summary.unverified > 0);
  assert.equal(summary.measured + summary.not_run + summary.unverified, summary.total);
  // 1~11단계를 한 기록표로 표현한다(예전 20개 제한보다 많다).
  assert.ok(byId.size > 20);
  assert.deepEqual([...new Set([...byId.values()].map(r => r.stage))].sort((a, b) => a - b),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
});

test('요청 수 상한에 닿으면 남은 시험은 보내지 않고 미실행으로 남는다', async () => {
  const deployment = createFakeDeployment();
  const byId = await run(deployment, { maxRequests: 3 });
  assert.equal(deployment.calls.length, 3);
  assert.equal(sentCount(byId), 3);
  assert.equal(byId.get('device_status_get_method_denied').status, 'not_run');
  assert.match(byId.get('device_status_get_method_denied').reason, /상한/u);
});

test('요청은 문자열 주소와 필요한 옵션만으로 보내 엄격한 가로채기 환경에서도 기록된다', async () => {
  const deployment = createFakeDeployment();
  const seen = [];
  const strictFetch = async (url, init) => {
    if (typeof url !== 'string') throw new TypeError('url must be a string');
    if ('body' in init) throw new TypeError('body is not allowed on GET');
    seen.push(`${init.method} ${new URL(url).pathname}`);
    return deployment.fetch(url, init);
  };
  const records = await runAttackChecks(config, { fetch: strictFetch, delayMs: 0, env: {} });
  const sent = records.filter((record) => record.status === 'pass' || record.status === 'fail');
  assert.equal(sent.length, 9);
  assert.equal(seen.length, 9);
  assert.ok(sent.every((record) => Number.isInteger(record.httpStatus)));
});

test('기대 결과와 실제 결과가 다르면 fail로 기록된다', async () => {
  const deployment = createFakeDeployment({ overrides: {
    // 로그인 없이 목록이 열리는 잘못된 배포
    'GET /api/notes': () => new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    // 상태는 맞지만 오류 코드가 다름
    'GET /api/notes/00000000-0000-4000-8000-000000000000': () => new Response('{"error":"SOMETHING_ELSE"}',
      { status: 401, headers: { 'content-type': 'application/json' } }),
    // 보안 헤더 누락
    'GET /': () => new Response('<html></html>', { status: 200, headers: { 'content-type': 'text/html' } }),
  } });
  const byId = await run(deployment);
  const leaked = byId.get('anonymous_notes_list_denied');
  assert.equal(leaked.status, 'fail');
  assert.equal(leaked.httpStatus, 200);
  assert.match(leaked.reason, /기대 상태 401/u);
  assert.equal(byId.get('anonymous_note_by_id_denied').status, 'fail');
  assert.match(byId.get('anonymous_note_by_id_denied').reason, /오류 코드/u);
  assert.equal(byId.get('root_page_nosniff').status, 'fail');
  assert.match(byId.get('root_page_nosniff').reason, /x-content-type-options/u);
  // 같은 배포의 맞는 응답은 여전히 pass다.
  assert.equal(byId.get('login_get_method_denied').status, 'pass');
});

test('응답을 받지 못한 요청은 fail이며 응답 값을 만들어 넣지 않는다', async () => {
  const deployment = createFakeDeployment();
  const failing = async (url, init) => {
    if (new URL(url).pathname === '/api/notes' && !init.headers?.cookie) throw new TypeError('fetch failed secret-detail');
    return deployment.fetch(url, init);
  };
  const records = await runAttackChecks(config, { fetch: failing, delayMs: 0, env: {} });
  const record = records.find(r => r.testId === 'anonymous_notes_list_denied');
  assert.equal(record.status, 'fail');
  for (const field of ['httpStatus', 'errorCode', 'headers', 'requestId', 'requestIdSource']) {
    assert.equal(record[field], null, field);
  }
  assert.ok(record.checkedAt);
  assert.ok(!JSON.stringify(record).includes('secret-detail'));
});

test('확인 시각은 요청을 실행한 시점의 ISO 8601 값이다', async () => {
  const base = Date.now() - 120000;
  let tick = 0;
  const instants = [];
  const deployment = createFakeDeployment();
  const fetchSpy = async (url, init) => {
    instants.push(instants.length); // 요청 순서
    return deployment.fetch(url, init);
  };
  const records = await runAttackChecks(config, {
    fetch: fetchSpy, delayMs: 0, env: {}, now: () => new Date(base + (tick++) * 1000),
  });
  const sent = records.filter(r => r.checkedAt !== null);
  assert.equal(sent.length, deployment.calls.length);
  sent.forEach((record, index) => {
    assert.equal(record.checkedAt, new Date(base + index * 1000).toISOString());
    assert.match(record.checkedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u);
  });
  assert.ok(records.filter(r => r.checkedAt === null).every(r => r.status === 'not_run' || r.status === 'unverified'));
});

test('비밀값·토큰·쿠키·메모 본문은 기록하거나 출력하지 않는다', async () => {
  const printed = [];
  const originalWrite = [process.stdout.write, process.stderr.write];
  process.stdout.write = (chunk) => { printed.push(String(chunk)); return true; };
  process.stderr.write = (chunk) => { printed.push(String(chunk)); return true; };
  let records;
  try {
    records = await runAttackChecks(config, {
      fetch: createFakeDeployment().fetch, delayMs: 0, env: SESSION_ENV,
    });
  } finally {
    [process.stdout.write, process.stderr.write] = originalWrite;
  }
  assert.ok(records.some(r => r.testId === 'own_note_read_with_device_session' && r.status === 'pass'));
  const text = JSON.stringify(records) + printed.join('');
  for (const secret of [TEST_LOGIN_TOKEN, TEST_DEVICE_TOKEN, SECRET_NOTE_BODY, SECRET_NOTE_TITLE,
    SECRET_NOTE_ID, SECRET_SET_COOKIE, 'SECRET_COOKIE_VALUE', '__Host-byte-back', 'set-cookie', 'cookie']) {
    assert.ok(!text.toLowerCase().includes(secret.toLowerCase()), `기록에 ${secret} 가 있음`);
  }
  // 기록된 헤더는 허용 목록뿐이다.
  const allowed = new Set(['allow', 'cache-control', 'content-type', 'x-content-type-options']);
  for (const record of records) {
    for (const name of Object.keys(record.headers ?? {})) assert.ok(allowed.has(name), name);
  }
  // 경로에는 실제 메모 ID가 아니라 :id 모양만 남는다.
  assert.ok(records.every(r => !/[0-9a-f]{8}-[0-9a-f]{4}-/iu.test(r.path)));
});

test('기록 검증은 가짜 응답·가짜 성공·비밀값을 거부한다', () => {
  assert.doesNotThrow(() => validateAttackRecords([fakeRecord(), unsentRecord({ testId: 'other', status: 'unverified' })]));
  const rejected = (record, pattern) => assert.throws(() => validateAttackRecords([record]), pattern);
  // 보내지 않은 시험에 응답 값
  rejected(unsentRecord({ httpStatus: 401 }), /httpStatus는 null/u);
  rejected(unsentRecord({ requestId: 'abcdefgh1234' }), /requestId는 null/u);
  rejected(unsentRecord({ checkedAt: new Date().toISOString() }), /checkedAt는 null/u);
  rejected(unsentRecord({ status: 'unverified', observed: 'HTTP 200' }), /observed는 null/u);
  rejected(unsentRecord({ reason: null }), /사유/u);
  // 기대와 다른 상태 코드를 pass로 기록
  rejected(fakeRecord({ httpStatus: 200 }), /pass일 수 없습니다/u);
  // 응답 없이 pass, 시각 없이 pass, 미래 시각
  rejected(fakeRecord({ httpStatus: null, errorCode: null, headers: null }), /fail이어야/u);
  rejected(fakeRecord({ checkedAt: null }), /checkedAt/u);
  rejected(fakeRecord({ checkedAt: new Date(Date.now() + 3600000).toISOString() }), /checkedAt/u);
  // 요청 ID는 허용된 응답 헤더에서 읽은 값만
  rejected(fakeRecord({ requestId: 'abcdefgh1234', requestIdSource: null }), /requestId/u);
  rejected(fakeRecord({ requestId: 'abcdefgh1234', requestIdSource: 'x-made-up' }), /requestId/u);
  assert.doesNotThrow(() => validateAttackRecords([fakeRecord({ requestId: 'abcdefgh1234', requestIdSource: 'x-vercel-id' })]));
  // 허용 목록 밖 헤더, 비밀값, 알 수 없는 필드, 쿼리가 있는 경로, 중복 ID
  rejected(fakeRecord({ headers: { 'set-cookie': 'a=b' } }), /headers/u);
  rejected(fakeRecord({ observed: `key ${'sk-'}${'a'.repeat(24)}` }), /비밀값/u);
  rejected(fakeRecord({ observed: '__Host-byte-back-session=abc' }), /비밀값/u);
  rejected({ ...fakeRecord(), body: '메모 본문' }, /필드는/u);
  rejected(fakeRecord({ path: '/api/notes?id=1' }), /path/u);
  rejected(fakeRecord({ status: 'success' }), /status/u);
  assert.throws(() => validateAttackRecords([fakeRecord(), fakeRecord()]), /중복/u);
  assert.throws(() => validateAttackRecords([]), /1~/u);
  // 20개를 넘는 기록표도 허용한다(1~11단계 전체).
  const many = Array.from({ length: 45 }, (_, i) => unsentRecord({ testId: `t${i}` }));
  assert.doesNotThrow(() => validateAttackRecords(many));
});

// ---- scripts/bundle.mjs: 임시 Git 저장소에서 실제 스크립트를 실행한다. 요청은 가상 배포로만 나간다. ----
function makeBundleRepo(checkerSource) {
  const dir = mkdtempSync(join(tmpdir(), 'bundle-test-'));
  mkdirSync(join(dir, 'scripts'));
  mkdirSync(join(dir, 'src'));
  cpSync(join(root, 'scripts', 'bundle.mjs'), join(dir, 'scripts', 'bundle.mjs'));
  for (const name of ['attack-check.mjs', 'attack-record.mjs', 'decider.mjs', 'device-session.mjs']) {
    cpSync(join(root, 'src', name), join(dir, 'src', name));
  }
  if (checkerSource) writeFileSync(join(dir, 'src', 'attack-check.mjs'), checkerSource);
  writeFileSync(join(dir, 'package.json'), '{"type":"module"}\n');
  writeFileSync(join(dir, '.gitignore'), 'artifacts/\nbundle-notes.json\n');
  writeFileSync(join(dir, 'aleph.config.json'), `${JSON.stringify({
    step: 1, repoUrl: 'https://github.com/test-user/test-repo',
    publicAppUrl: 'https://student-defense.vercel.app/', sampleMarker: SAMPLE_MARKER,
    judgeIssuer: 'https://judge.example.test/defense/judge',
  })}\n`);
  writeFileSync(join(dir, 'bundle-notes.json'), '{"explanation":"시험용 설명입니다. 한 일 세 줄."}\n');
  const git = (...args) => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8' });
  git('init', '-q');
  git('remote', 'add', 'origin', 'https://github.com/test-user/test-repo');
  git('add', '.');
  git('-c', 'user.name=test', '-c', 'user.email=test', 'commit', '-q', '-m', 'test');
  return dir;
}
function runBundle(dir) {
  const env = { ...process.env };
  delete env[ATTACK_ENV.login];
  delete env[ATTACK_ENV.device];
  return spawnSync(process.execPath, ['--import', pathToFileURL(join(root, 'test', 'helpers', 'fake-fetch-preload.mjs')).href,
    join(dir, 'scripts', 'bundle.mjs')], { cwd: dir, env, encoding: 'utf8', timeout: 60000 });
}

test('bundle.mjs는 채점표 형식의 attackAttempts를 내보내고 보내지 않은 시험은 not_run으로 둔다', () => {
  const dir = makeBundleRepo();
  try {
    const result = runBundle(dir);
    assert.equal(result.status, 0, result.stderr);
    const bundle = JSON.parse(readFileSync(join(dir, 'artifacts', 'submission.json'), 'utf8'));
    assert.equal(bundle.schema, 'aleph.defense.submission.v2');
    assert.equal(bundle.attackRecords, undefined);
    assert.equal(bundle.attackSummary, undefined);
    assert.ok(bundle.attackAttempts.length >= 1 && bundle.attackAttempts.length <= 20);
    for (const attempt of bundle.attackAttempts) {
      assert.deepEqual(Object.keys(attempt).sort(), ['attackId', 'expected', 'observed']);
    }
    // 실제로 요청을 보낸 시험(GET 9건)은 받은 HTTP 상태가 observed에 그대로 적힌다.
    const observed = new Map(bundle.attackAttempts.map(a => [a.attackId, a.observed]));
    const sent = {
      anonymous_note_read: 'HTTP 200', root_page_nosniff: 'HTTP 200', aleph_json_public: 'HTTP 200',
      anonymous_notes_list_denied: 'HTTP 401', anonymous_note_by_id_denied: 'HTTP 401',
      login_get_method_denied: 'HTTP 405', unknown_api_route_denied: 'HTTP 404',
      restore_get_method_denied: 'HTTP 405', device_status_get_method_denied: 'HTTP 405',
    };
    for (const [id, status] of Object.entries(sent)) assert.equal(observed.get(id), status, id);
    // 그 밖의 항목은 보내지 않았으므로 not_run이다(쓰기 요청 시험 포함).
    for (const attempt of bundle.attackAttempts) {
      if (!(attempt.attackId in sent)) assert.equal(attempt.observed, 'not_run', attempt.attackId);
    }
    assert.equal(observed.get('anonymous_note_create_denied') ?? 'not_run', 'not_run');
    // artifacts에는 제출 묶음 하나만 만들어진다. 부가 파일은 쓰지 않는다.
    assert.deepEqual(readdirSync(join(dir, 'artifacts')), ['submission.json']);
    assert.doesNotMatch(result.stdout + result.stderr, /cookie|SECRET/iu);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('attackAttempts 변환은 실제 HTTP 상태만 적고 보내지 않은 시험은 not_run으로 둔다', () => {
  const sentRecord = (testId, over = {}) => fakeRecord({ testId, ...over });
  const attempts = toAttackAttempts([
    sentRecord('sent_pass'),
    sentRecord('sent_fail', { status: 'fail', httpStatus: 200, reason: '기대 상태 401과 다름' }),
    sentRecord('no_response', { status: 'fail', httpStatus: null, errorCode: null, headers: null }),
    unsentRecord({ testId: 'not_run_write', method: 'POST' }),
    unsentRecord({ testId: 'unverified_one', status: 'unverified' }),
  ]);
  assert.deepEqual(attempts.map(a => [a.attackId, a.observed]), [
    ['sent_pass', 'HTTP 401'], ['sent_fail', 'HTTP 200'], ['no_response', 'not_run'],
    ['not_run_write', 'not_run'], ['unverified_one', 'not_run'],
  ]);
  assert.ok(attempts.every(a => Object.keys(a).sort().join() === 'attackId,expected,observed'));
  assert.doesNotThrow(() => validateAttackAttempts(attempts));
});

test('HTTP 응답을 받지 못한 시험은 상태를 지어내지 않고 not_run으로 둔다', async () => {
  const records = await runAttackChecks(config, {
    fetch: async () => { throw new TypeError('fetch failed'); }, delayMs: 0, env: {},
  });
  const attempts = toAttackAttempts(records);
  const sentIds = records.filter(r => r.status === 'fail').map(r => r.testId);
  assert.equal(sentIds.length, 9); // 시도한 GET 9건은 모두 응답이 없다
  for (const attempt of attempts) assert.equal(attempt.observed, 'not_run', attempt.attackId);
  assert.ok(attempts.every(a => !a.observed.startsWith('HTTP') && a.observed !== 'no_response'));
});

test('attackAttempts가 20개를 넘으면 실제로 보낸 시험을 먼저 넣고 표 순서를 지킨다', () => {
  const records = [];
  for (let i = 0; i < 30; i += 1) records.push(unsentRecord({ testId: `u${i}`, method: i % 2 ? 'GET' : 'POST' }));
  records.splice(5, 0, fakeRecord({ testId: 'sent_a' }));
  records.push(fakeRecord({ testId: 'sent_b' }));
  const attempts = toAttackAttempts(records);
  assert.equal(attempts.length, 20);
  const ids = attempts.map(a => a.attackId);
  assert.ok(ids.includes('sent_a') && ids.includes('sent_b'));
  // 쓰기 요청이라 보내지 않은 시험 15개가 모두 들어가고, 남은 3자리만 읽기 시험이 표 순서대로 채운다.
  const picked = ids.map(id => records.find(r => r.testId === id));
  assert.equal(picked.filter(r => r.method === 'POST').length, 15);
  assert.deepEqual(picked.filter(r => r.method === 'GET' && r.status === 'not_run').map(r => r.testId), ['u1', 'u3', 'u5']);
  assert.deepEqual(ids, records.map(r => r.testId).filter(id => ids.includes(id)));
  assert.throws(() => validateAttackAttempts(records.map(toAttackAttempt)), /1~20/u);
  assert.throws(() => validateAttackAttempts([{ attackId: 'x', expected: 'y' }]), /attackId·expected·observed/u);
  assert.throws(() => validateAttackAttempts([toAttackAttempt(records[0]), toAttackAttempt(records[0])]), /중복/u);
});

test('bundle.mjs는 예전 attackId·expected·observed 형식과 가짜 기록을 거부한다', () => {
  const legacy = makeBundleRepo(`export async function runAttackChecks() {
    return [{ attackId: 'anonymous_note_read', expected: '확인', observed: '확인됨' }];
  }\n`);
  const forged = makeBundleRepo(`export async function runAttackChecks() {
    return [{ stage: 3, testId: 'forged', kind: 'forbidden', method: 'GET', path: '/api/notes',
      expected: '거부', expectedStatus: [401], status: 'not_run', httpStatus: 401, errorCode: null,
      headers: null, requestId: 'made-up-id-123', requestIdSource: 'x-vercel-id', checkedAt: null,
      observed: null, reason: '보내지 않음' }];
  }\n`);
  try {
    for (const dir of [legacy, forged]) {
      const result = runBundle(dir);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /제출 묶음 생성 중 첫 오류: 시험 기록/u);
    }
  } finally {
    rmSync(legacy, { recursive: true, force: true });
    rmSync(forged, { recursive: true, force: true });
  }
});
