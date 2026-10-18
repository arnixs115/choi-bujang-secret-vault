// 사용: node scripts/xdr-web-injection-test.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { respond, extractAlertId, RULE_TTL_MS } from '../xdr/web-injection/respond.mjs';
import { guardedDecide, isXdrRuleId } from '../src/xdr-guard.mjs';

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const tmp = await mkdtemp(path.join(os.tmpdir(), 'xdr-wi-'));
let n = 0;
const paths = () => ({ rulesPath: path.join(tmp, `rules-${++n}.json`), alertsLogPath: path.join(tmp, `alerts-${n}.log`) });
const T0 = Date.parse('2026-10-18T00:00:00Z');
const SQLI = "GET /s?q=1' UNION SELECT password FROM users--";
const attack = (over = {}) => ({ id: 'a-1', src_ip: '198.51.100.7', request: SQLI, ...over });
const BLOCK = { action: 'block', confidence: 0.95, reason: 'sql injection' };

test('명확한 block은 규칙 등록(만료 15분·근거 경보 번호·deny)', async () => {
  const p = paths();
  const r = await respond(attack(), BLOCK, { now: T0, ...p });
  assert.equal(r.rule.status, 'registered');
  const rule = r.rule.rule;
  assert.equal(rule.effect, 'deny');
  assert.equal(rule.sourceIp, '198.51.100.7');
  assert.equal(rule.evidenceAlertId, 'a-1');
  assert.equal(Date.parse(rule.expiresAt) - T0, RULE_TTL_MS);
  assert.ok(isXdrRuleId(rule.id));
});

test('확신도 0.85 미만, alert, record는 등록하지 않음', async () => {
  for (const d of [{ action: 'block', confidence: 0.84 }, { action: 'alert', confidence: 0.99 }, { action: 'record', confidence: 0.99 }]) {
    const r = await respond(attack(), d, { now: T0, ...paths() });
    assert.equal(r.rule.status, 'skipped');
  }
  const edge = await respond(attack(), { action: 'block', confidence: 0.85 }, { now: T0, ...paths() });
  assert.equal(edge.rule.status, 'registered');
});

test('경보 ID·IP·근거가 없거나 잘못되면 등록하지 않음', async () => {
  const cases = [
    [attack({ id: undefined }), 'missing_alert_id'],
    [attack({ src_ip: undefined }), 'missing_source_ip'],
    [attack({ src_ip: '999.1.1.1' }), 'invalid_source_ip'],
    [attack({ src_ip: '127.0.0.1' }), 'non_blockable_ip'],
    [attack({ request: 'GET /index.html' }), 'no_attack_evidence'],
    [attack({ request: 'SQL injection suspected (설명문만 있음)' }), 'no_attack_evidence'],
  ];
  for (const [alert, why] of cases) {
    const r = await respond(alert, BLOCK, { now: T0, ...paths() });
    assert.equal(r.rule.status, 'skipped');
    assert.equal(r.rule.skipReason, why);
  }
  const mismatch = await respond(attack(), { ...BLOCK, alertId: 'other' }, { now: T0, ...paths() });
  assert.equal(mismatch.rule.skipReason, 'alert_id_mismatch');
});

test('URL 인코딩된 페이로드도 근거로 인정', async () => {
  const r = await respond(attack({ request: 'GET /s?q=1%27%20UNION%20SELECT%20x' }), BLOCK, { now: T0, ...paths() });
  assert.equal(r.rule.status, 'registered');
});

test('같은 IP 중복 등록 방지', async () => {
  const p = paths();
  await respond(attack(), BLOCK, { now: T0, ...p });
  const r = await respond(attack({ id: 'a-2' }), BLOCK, { now: T0 + 1000, ...p });
  assert.equal(r.rule.status, 'duplicate');
});

test('알림 로그는 경보당 한 줄 JSONL로 누적(skipped 포함)', async () => {
  const p = paths();
  await respond(attack(), BLOCK, { now: T0, ...p });
  await respond(attack({ id: 'a-3', src_ip: '198.51.100.8', request: 'GET /' }), { action: 'record', confidence: 0.1 }, { now: T0, ...p });
  await respond(attack({ id: 'a-4', src_ip: '198.51.100.9' }), BLOCK, { now: T0, ...p });
  const lines = (await readFile(p.alertsLogPath, 'utf8')).trimEnd().split('\n');
  assert.equal(lines.length, 3);
  const rows = lines.map((l) => JSON.parse(l));
  for (const k of ['ts', 'alertId', 'action', 'confidence', 'reason', 'ruleResult', 'expiresAt']) assert.ok(k in rows[0], k);
  assert.equal(rows[0].ruleResult.status, 'registered');
  assert.equal(rows[1].ruleResult.status, 'skipped');
  assert.equal(rows[1].expiresAt, null);
});

test('파일 입출력 오류와 규칙 등록 실패를 구분', async () => {
  const blocker = path.join(tmp, 'plainfile');
  await writeFile(blocker, 'x');
  const io = await respond(attack(), BLOCK, { now: T0, rulesPath: path.join(blocker, 'r.json'), alertsLogPath: path.join(blocker, 'a.log') });
  assert.equal(io.rule.status, 'failed');
  assert.equal(io.rule.errorKind, 'io_error');
  assert.equal(io.log.ok, false);
  assert.equal(io.log.errorKind, 'io_error');

  const p = paths();
  await writeFile(p.rulesPath, '{broken');
  const corrupt = await respond(attack(), BLOCK, { now: T0, ...p });
  assert.equal(corrupt.rule.status, 'failed');
  assert.equal(corrupt.rule.errorKind, 'registration_failed');
  assert.equal(corrupt.log.ok, true);
});

test('guard: 만료 전 같은 IP 거부(규칙 ID·근거 경보 포함), 만료 후·다른 IP·IP 없음은 통과', async () => {
  const p = paths();
  await respond(attack(), BLOCK, { now: T0, ...p });
  const passed = { decision: 'allow', marker: 'from-decider' };
  const calls = [];
  const decide = (req) => { calls.push(req); return passed; };
  const req = { path: '/notes/1' };

  const denied = await guardedDecide(req, { sourceIp: '198.51.100.7', now: T0 + 60_000, rulesPath: p.rulesPath, decide });
  assert.equal(denied.decision, 'deny');
  assert.ok(isXdrRuleId(denied.ruleId));
  assert.equal(denied.evidenceAlertId, 'a-1');
  assert.equal(calls.length, 0, '거부 시 기존 판정기를 호출하지 않아야 함');

  const justBefore = await guardedDecide(req, { sourceIp: '198.51.100.7', now: T0 + RULE_TTL_MS - 1, rulesPath: p.rulesPath, decide });
  assert.equal(justBefore.decision, 'deny');
  const expired = await guardedDecide(req, { sourceIp: '198.51.100.7', now: T0 + RULE_TTL_MS, rulesPath: p.rulesPath, decide });
  assert.equal(expired, passed);
  const other = await guardedDecide(req, { sourceIp: '198.51.100.99', now: T0 + 60_000, rulesPath: p.rulesPath, decide });
  assert.equal(other, passed);
  const none = await guardedDecide(req, { now: T0 + 60_000, rulesPath: p.rulesPath, decide });
  assert.equal(none, passed);
});

test('guard: 요청 본문의 IP 필드는 출발지로 쓰지 않음', async () => {
  const p = paths();
  await respond(attack(), BLOCK, { now: T0, ...p });
  const passed = { decision: 'allow' };
  const r = await guardedDecide({ sourceIp: '198.51.100.7', src_ip: '198.51.100.7' },
    { sourceIp: '203.0.113.5', now: T0 + 1000, rulesPath: p.rulesPath, decide: () => passed });
  assert.equal(r, passed);
});

test('guard: 규칙 파일이 손상돼도 기존 판정기로 넘기고 경고만 남김', async () => {
  const p = paths();
  await writeFile(p.rulesPath, '{broken');
  const passed = { decision: 'allow' };
  let warned = 0;
  const r = await guardedDecide({}, { sourceIp: '198.51.100.7', rulesPath: p.rulesPath, decide: () => passed, onWarning: () => warned++ });
  assert.equal(r, passed);
  assert.equal(warned, 1);
});

test('IPv4-mapped IPv6 주소도 같은 IP로 취급', async () => {
  const p = paths();
  await respond(attack({ src_ip: '::ffff:198.51.100.7' }), BLOCK, { now: T0, ...p });
  const r = await guardedDecide({}, { sourceIp: '198.51.100.7', now: T0 + 1000, rulesPath: p.rulesPath, decide: () => ({ decision: 'allow' }) });
  assert.equal(r.decision, 'deny');
});

test('src/decider.mjs · ZTNA 관련 파일에 미커밋 변경이 없음(git 필요)', async () => {
  let out;
  try {
    out = execFileSync('git', ['status', '--porcelain', '--', 'src/decider.mjs', 'xdr/web-injection/decide.mjs', 'scripts/xdr-run.mjs', 'xdr/brute-force'], { encoding: 'utf8' });
  } catch { return 'skip'; }
  assert.equal(out.trim(), '', `변경됨:\n${out}`);
});

// ── 실제 fixture + 실제 decide.mjs 시험 (파일이 있을 때만) ─────────────
const ids = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => `wi-${String(from + i).padStart(2, '0')}`);
const BLOCK_IDS = new Set([...ids(1, 5), 'wi-07', 'wi-08']);
const NEVER_IDS = new Set([...ids(15, 17), ...ids(18, 26)]);

test('fixture: wi-15~17, wi-18~26은 규칙을 만들지 않고, 등록된 건은 모두 block', async () => {
  const fixtureUrl = new URL('../xdr/fixtures/web-injection.json', import.meta.url);
  const decideUrl = new URL('../xdr/web-injection/decide.mjs', import.meta.url);
  if (!existsSync(fixtureUrl) || !existsSync(decideUrl)) return 'skip';
  const mod = await import(decideUrl);
  const decide = mod.decide ?? mod.default;
  const fx = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const alerts = Array.isArray(fx) ? fx : (fx.alerts ?? fx.events ?? fx.items);
  const p = paths();
  const notRegistered = [];
  let registered = 0;
  for (const alert of alerts) {
    const decision = await decide(alert);
    const r = await respond(alert, decision, { now: T0, ...p });
    const id = extractAlertId(alert);
    if (NEVER_IDS.has(id)) assert.equal(r.rule.status, 'skipped', `${id}는 규칙이 없어야 함`);
    if (r.rule.status === 'registered') {
      registered += 1;
      assert.equal(decision.action, 'block', `${id}`);
      assert.ok(r.rule.rule.expiresAt && r.rule.rule.evidenceAlertId);
    } else if (BLOCK_IDS.has(id)) {
      notRegistered.push(`${id}(${r.rule.skipReason ?? r.rule.errorKind})`);
    }
  }
  const logLines = (await readFile(p.alertsLogPath, 'utf8')).trimEnd().split('\n').length;
  assert.equal(logLines, alerts.length);
  console.log(`    · fixture 등록 ${registered}건 / 로그 ${logLines}줄 / block 대상인데 미등록: ${notRegistered.join(', ') || '없음'}`);
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    const res = await fn();
    console.log(res === 'skip' ? `건너뜀 · ${name}` : `통과 · ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`실패 · ${name}\n    ${err.message.split('\n').join('\n    ')}`);
  }
}
await rm(tmp, { recursive: true, force: true });
console.log(`${tests.length - failed}/${tests.length} 완료 (건너뜀 포함). 가상 요청 시험이며 실제 ZTNA 엔진 집행 증거가 아닙니다.`);
process.exitCode = failed ? 1 : 0;
