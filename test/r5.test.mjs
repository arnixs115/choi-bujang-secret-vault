import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const calls = [];
  const fakeFetch = (body, status = 200) => async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(body, { status, headers: { 'content-type': 'application/json' } });
  };
  // 이 시험은 /data.json 점검 하나만 본다. 나머지 요청은 아래 상한(1건)으로 보내지 않는다.
  const options = { delayMs: 0, maxRequests: 1, env: {} };
  const good = JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] });
  const [result] = await runAttackChecks(config, { ...options, fetch: fakeFetch(good) });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://student-defense.vercel.app/data.json');
  assert.equal(calls[0].init.redirect, 'error');
  assert.equal(calls[0].init.headers.cookie, undefined);
  assert.equal(result.testId, 'anonymous_note_read');
  assert.equal(result.status, 'pass');
  assert.match(result.observed, /확인 표시가 보임/u);
  const [failed] = await runAttackChecks(config, { ...options, fetch: fakeFetch('<html>not the data</html>') });
  assert.equal(failed.status, 'fail');
  assert.match(failed.observed, /보이지 않음/u);
});
