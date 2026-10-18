// 작전실 화면(public/operations-room.js)과 결과 파일 생성(scripts/write-attack-results.mjs) 시험.
// 응답은 test/helpers/fake-deployment.mjs 의 가상 응답이며 실제 배포 결과가 아니다.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runAttackChecks } from '../src/attack-check.mjs';
import { buildAttackResults } from '../scripts/write-attack-results.mjs';
import {
  RESULTS_SCHEMA, countStatuses, describeRecord, readResults,
} from '../public/operations-room.js';
import {
  SECRET_NOTE_BODY, SECRET_SET_COOKIE, TEST_DEVICE_TOKEN, TEST_LOGIN_TOKEN, createFakeDeployment,
} from './helpers/fake-deployment.mjs';

const config = { step: 12, publicAppUrl: 'https://student-defense.vercel.app/', sampleMarker: 'SAMPLE_NOTE_1' };
const sent = (over = {}) => ({
  stage: 3, testId: 'a', kind: 'forbidden', method: 'GET', path: '/api/notes', status: 'pass', httpStatus: 401,
  errorCode: 'UNAUTHORIZED', headers: {}, requestId: null, requestIdSource: null,
  checkedAt: '2026-10-18T04:00:00.000Z', observed: 'HTTP 401', reason: null, ...over,
});
const unsent = (over = {}) => ({
  stage: 9, testId: 'b', kind: 'forbidden', method: 'GET', path: '/api/notes', status: 'not_run', httpStatus: null,
  errorCode: null, headers: null, requestId: null, requestIdSource: null, checkedAt: null, observed: null,
  reason: '보내지 않음', ...over,
});
const file = (records) => ({ schema: RESULTS_SCHEMA, generatedAt: '2026-10-18T04:00:01.000Z', records });

test('결과 파일이 아니거나 비어 있으면 화면은 결과를 쓰지 않는다', () => {
  for (const data of [null, [], {}, { ...file([sent()]), schema: 'other' }, file([]),
    { ...file([sent()]), generatedAt: 'not a date' }]) {
    assert.equal(readResults(data).ok, false);
  }
  assert.equal(readResults(file([sent()])).ok, true);
});

test('보내지 않은 시험에 응답 값이 있거나 응답 없이 통과로 적힌 파일은 쓰지 않는다', () => {
  assert.equal(readResults(file([unsent({ httpStatus: 200 })])).ok, false);
  assert.equal(readResults(file([unsent({ status: 'unverified', requestId: 'abcdefgh12' })])).ok, false);
  assert.equal(readResults(file([sent({ httpStatus: null })])).ok, false);
  assert.equal(readResults(file([sent({ status: 'success' })])).ok, false);
});

test('집계는 파일에 있는 기록만 세고 미실행·미확인은 실측에 넣지 않는다', () => {
  const records = [sent(), sent({ testId: 'c', status: 'fail', httpStatus: 200 }),
    unsent(), unsent({ testId: 'd', status: 'unverified' }), unsent({ testId: 'e' })];
  assert.deepEqual(countStatuses(records),
    { total: 5, pass: 1, fail: 1, not_run: 2, unverified: 1, measured: 2 });
});

test('화면 문구는 없는 값을 채우지 않는다', () => {
  const noId = describeRecord(sent());
  assert.equal(noId.requestId, '없음');
  assert.equal(noId.http, '401');
  assert.equal(noId.checkedAt, '2026-10-18T04:00:00.000Z');
  const notRun = describeRecord(unsent());
  assert.equal(notRun.status, '미실행');
  assert.equal(notRun.http, '—');
  assert.equal(notRun.requestId, '—');
  assert.equal(notRun.checkedAt, '—');
  assert.equal(describeRecord(unsent({ status: 'unverified' })).status, '미확인');
});

test('실제 점검기 결과로 만든 파일은 화면이 그대로 읽고 비밀값이 없다', async () => {
  const records = await runAttackChecks(config, {
    fetch: createFakeDeployment().fetch, delayMs: 0,
    env: { ATTACK_CHECK_LOGIN_TOKEN: TEST_LOGIN_TOKEN, ATTACK_CHECK_DEVICE_TOKEN: TEST_DEVICE_TOKEN },
  });
  const results = buildAttackResults(records, new Date('2026-10-18T04:10:00.000Z'));
  assert.equal(results.schema, RESULTS_SCHEMA);
  assert.equal(results.generatedAt, '2026-10-18T04:10:00.000Z');
  const parsed = readResults(JSON.parse(JSON.stringify(results)));
  assert.equal(parsed.ok, true);
  const counts = countStatuses(parsed.records);
  assert.equal(counts.pass, results.summary.pass);
  assert.equal(counts.fail, results.summary.fail);
  assert.equal(counts.not_run, results.summary.not_run);
  assert.equal(counts.unverified, results.summary.unverified);
  const text = JSON.stringify(results).toLowerCase();
  for (const secret of [TEST_LOGIN_TOKEN, TEST_DEVICE_TOKEN, SECRET_NOTE_BODY, SECRET_SET_COOKIE, 'set-cookie']) {
    assert.ok(!text.includes(secret.toLowerCase()), secret);
  }
});

test('검증을 통과하지 못한 기록으로는 결과 파일을 만들지 않는다', () => {
  assert.throws(() => buildAttackResults([unsent({ httpStatus: 200 })]), /httpStatus/u);
  assert.throws(() => buildAttackResults([]), /1~/u);
});

test('작전실 화면에는 하드코딩한 결과가 없고 결과 파일만 읽는다', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const script = await readFile(new URL('../public/operations-room.js', import.meta.url), 'utf8');
  assert.match(html, /<section id="operations-room"/u);
  assert.match(html, /src="\/operations-room\.js"/u);
  assert.match(script, /\/attack-results\.json/u);
  assert.doesNotMatch(script, /innerHTML|insertAdjacentHTML|document\.write/u);
  // 숫자는 파일에서 읽은 값으로만 채워지므로 HTML에 통과·실패 개수가 적혀 있으면 안 된다.
  assert.doesNotMatch(html.slice(html.indexOf('id="operations-room"'), html.indexOf('id="install-title"')),
    /통과\s*\d|실패\s*\d|미실행\s*\d/u);
});
