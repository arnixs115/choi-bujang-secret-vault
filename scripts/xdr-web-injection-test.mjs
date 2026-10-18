// 사용: node scripts/xdr-web-injection-test.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { respond, extractAlertId, RULE_TTL_MS } from '../xdr/web-injection/respond.mjs';
import { guardedDecide, guardedDecideDetailed, isXdrRuleId } from '../src/xdr-guard.mjs';
import { fixtureRequests } from './fixture-7.mjs';

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const tmp = await mkdtemp(path.join(os.tmpdir(), 'xdr-wi-'));
let n = 0;
const paths = () => ({ rulesPath: path.join(tmp, `rules-${++n}.json`), alertsLogPath: path.join(tmp, `alerts-${n}.log`) });
const T0 = Date.parse('2026-10-18T00:00:00Z');
// 실제 fixture와 같은 모양: { id, rule:{description,...}, data:{ srcip, url, count(문자열) } }
const URL_SQLI = "/notes?q=1' UNION SELECT password FROM users--";
const DESC_SQL = '같은 주소에서 SQL 구문을 이어 붙인 요청이 12번 반복됐습니다.';
const attack = (over = {}) => {
  const o = { id: 'a-1', ip: '198.51.100.7', url: URL_SQLI, count: '12', description: DESC_SQL, ...over };
  const a = { id: o.id, rule: { level: 12, description: o.description, mitre: ['T1190'] }, data: { srcip: o.ip, url: o.url, count: o.count } };
  if (o.id === undefined) delete a.id;
  if (o.ip === undefined) delete a.data.srcip;
  return a;
};
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
    [attack({ ip: undefined }), 'missing_source_ip'],
    [attack({ ip: '999.1.1.1' }), 'invalid_source_ip'],
    [attack({ ip: '127.0.0.1' }), 'non_blockable_ip'],
    [attack({ url: '/notes' }), 'no_attack_evidence'],
    [attack({ url: '/notes?q=hello' }), 'no_attack_evidence'], // 설명문만 있고 URL 근거 없음
    [attack({ url: '/notes?q=doc-sql-chain', description: '자료 목록을 조회했습니다.' }), 'no_attack_evidence'], // 표식만, 설명 없음
    [attack({ url: '/notes?q=doc-sql-chain', count: '2' }), 'no_attack_evidence'], // 반복 부족
    [attack({ url: '/notes?q=doc-cmd-separator', description: '명령 구분자 표기가 연속 요청 11번에 있습니다.', count: '11' }), 'no_attack_evidence'], // decide.mjs도 record
  ];
  for (const [alert, why] of cases) {
    const r = await respond(alert, BLOCK, { now: T0, ...paths() });
    assert.equal(r.rule.status, 'skipped');
    assert.equal(r.rule.skipReason, why);
  }
  const mismatch = await respond(attack(), { ...BLOCK, alertId: 'other' }, { now: T0, ...paths() });
  assert.equal(mismatch.rule.skipReason, 'alert_id_mismatch');
});

test('URL 인코딩된 페이로드, fixture 표식(표식+설명+반복) 모두 근거로 인정', async () => {
  const enc = await respond(attack({ url: '/s?q=1%27%20UNION%20SELECT%20x' }), BLOCK, { now: T0, ...paths() });
  assert.equal(enc.rule.status, 'registered');
  const marker = await respond(attack({ url: '/notes?q=doc-sql-chain' }), BLOCK, { now: T0, ...paths() });
  assert.equal(marker.rule.status, 'registered');
  assert.match(marker.rule.rule.reason, /sql_injection/);
});

test('경보 본문의 다른 필드에 있는 IP는 출발지로 쓰지 않음(data.srcip만)', async () => {
  const a = attack({ ip: undefined });
  a.data.note = '198.51.100.7';
  a.srcip = '198.51.100.7';
  const r = await respond(a, BLOCK, { now: T0, ...paths() });
  assert.equal(r.rule.skipReason, 'missing_source_ip');
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
  await respond(attack({ id: 'a-3', ip: '198.51.100.8', url: '/' }), { action: 'record', confidence: 0.1 }, { now: T0, ...p });
  await respond(attack({ id: 'a-4', ip: '198.51.100.9' }), BLOCK, { now: T0, ...p });
  const lines = (await readFile(p.alertsLogPath, 'utf8')).trimEnd().split('\n');
  assert.equal(lines.length, 3);
  const rows = lines.map((l) => JSON.parse(l));
  for (const k of ['ts', 'moduleKey', 'alertId', 'action', 'confidence', 'reason', 'ruleResult', 'expiresAt']) assert.ok(k in rows[0], k);
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
  const req = { path: '/notes/1', requestId: 'req-1' };

  const denied = await guardedDecideDetailed(req, { sourceIp: '198.51.100.7', now: T0 + 60_000, rulesPath: p.rulesPath, decide });
  assert.equal(denied.response.decision, 'deny');
  assert.ok(isXdrRuleId(denied.response.ruleIds[0]));
  assert.equal(denied.xdr.ruleId, denied.response.ruleIds[0]);
  assert.equal(denied.xdr.evidenceAlertId, 'a-1');
  assert.equal(denied.xdr.expiresAt, new Date(T0 + RULE_TTL_MS).toISOString());
  assert.equal(calls.length, 0, '거부 시 기존 판정기를 호출하지 않아야 함');

  const justBefore = await guardedDecide(req, { sourceIp: '198.51.100.7', now: T0 + RULE_TTL_MS - 1, rulesPath: p.rulesPath, decide });
  assert.equal(justBefore.decision, 'deny');
  const expired = await guardedDecide(req, { sourceIp: '198.51.100.7', now: T0 + RULE_TTL_MS, rulesPath: p.rulesPath, decide });
  assert.equal(expired, passed);
  const other = await guardedDecideDetailed(req, { sourceIp: '198.51.100.99', now: T0 + 60_000, rulesPath: p.rulesPath, decide });
  assert.equal(other.response, passed);
  assert.equal(other.xdr, null);
  const none = await guardedDecide(req, { now: T0 + 60_000, rulesPath: p.rulesPath, decide });
  assert.equal(none, passed);
});

test('guard: 거부 응답은 판정기 계약의 5개 항목만 가짐(실제 decide와 같은 형식)', async () => {
  const p = paths();
  await respond(attack(), BLOCK, { now: T0, ...p });
  const { normal } = fixtureRequests();
  const KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

  const denied = await guardedDecide(normal, { sourceIp: '198.51.100.7', now: T0 + 1000, rulesPath: p.rulesPath });
  assert.equal(Object.keys(denied).sort().join(','), KEYS);
  assert.equal(denied.schema, 'aleph.decision.v1');
  assert.equal(denied.requestId, normal.requestId);
  assert.equal(denied.decision, 'deny');
  assert.match(denied.reasonCode, /^[a-z][a-z0-9_]{0,63}$/u);
  assert.ok(denied.ruleIds.length > 0 && denied.ruleIds.every(isXdrRuleId));

  // 규칙에 안 걸리면 기존 src/decider.mjs 결과와 같다(실제 판정기 호출).
  const { decide } = await import('../src/decider.mjs');
  const viaGuard = await guardedDecide(normal, { sourceIp: '192.0.2.250', now: T0 + 1000, rulesPath: p.rulesPath });
  assert.deepEqual(viaGuard, await decide(normal));
  assert.equal(viaGuard.decision, 'allow');
  assert.ok(!viaGuard.ruleIds.some(isXdrRuleId));
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
  await respond(attack({ ip: '::ffff:198.51.100.7' }), BLOCK, { now: T0, ...p });
  const r = await guardedDecide({}, { sourceIp: '198.51.100.7', now: T0 + 1000, rulesPath: p.rulesPath, decide: () => ({ decision: 'allow' }) });
  assert.equal(r.decision, 'deny');
});

test('src/decider.mjs · ZTNA 관련 파일에 미커밋 변경이 없음(git 필요)', async () => {
  let out;
  try {
    out = execFileSync('git', ['status', '--porcelain', '--untracked-files=no', '--', 'src/decider.mjs', 'xdr/web-injection/decide.mjs', 'scripts/xdr-run.mjs', 'xdr/brute-force'], { encoding: 'utf8' });
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
      notRegistered.push(`${id}(${r.rule.skipReason ?? r.rule.errorKind ?? r.rule.status})`);
    }
  }
  const logLines = (await readFile(p.alertsLogPath, 'utf8')).trimEnd().split('\n').length;
  assert.equal(logLines, alerts.length);
  console.log(`    · fixture 등록 ${registered}건 / 로그 ${logLines}줄 / block 대상인데 미등록: ${notRegistered.join(', ') || '없음'}`);
});

test('종단: fixture를 흘리면 공격 출발지만 거부, wi-15~26 출발지는 통과, 만료 후엔 모두 통과', async () => {
  const fixtureUrl = new URL('../xdr/fixtures/web-injection.json', import.meta.url);
  const decideUrl = new URL('../xdr/web-injection/decide.mjs', import.meta.url);
  if (!existsSync(fixtureUrl) || !existsSync(decideUrl)) return 'skip';
  const mod = await import(decideUrl);
  const decide = mod.decide ?? mod.default;
  const fx = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const alerts = Array.isArray(fx) ? fx : (fx.alerts ?? fx.events ?? fx.items);
  const p = paths();

  // 1) 경보를 흘려 규칙을 만든다.
  const attackIps = new Set();
  for (const alert of alerts) {
    const r = await respond(alert, await decide(alert), { now: T0, ...p });
    if (r.rule.status === 'registered' || r.rule.status === 'duplicate') attackIps.add(alert.data.srcip);
  }
  assert.ok(attackIps.size > 0, '등록된 공격 출발지가 없음(시험이 의미 없음)');

  // 2) 각 경보의 출발지에서 요청을 보내 본다. 판정기는 항상 allow인 시험용 대역.
  const allow = { decision: 'allow' };
  const ctx = (now) => ({ now, rulesPath: p.rulesPath, decide: () => allow });
  const wronglyBlocked = [];
  let deniedCount = 0;
  for (const alert of alerts) {
    const id = extractAlertId(alert);
    const ip = alert.data?.srcip;
    const { response: res, xdr } = await guardedDecideDetailed({ path: '/notes' }, { sourceIp: ip, ...ctx(T0 + 60_000) });
    const denied = res !== allow;
    if (denied) deniedCount += 1;
    assert.equal(denied, attackIps.has(ip), `${id}(${ip}): 공격 출발지만 거부되어야 함`);
    if (denied) {
      assert.equal(res.decision, 'deny');
      assert.ok(res.ruleIds?.[0] && xdr?.ruleId === res.ruleIds[0] && xdr.evidenceAlertId && xdr.expiresAt, `${id}: 거부에 규칙 ID·근거 경보·만료가 있어야 함`);
    }
    if (NEVER_IDS.has(id) && denied) wronglyBlocked.push(id);
  }
  assert.deepEqual(wronglyBlocked, [], `정상/애매 경보 출발지가 막힘: ${wronglyBlocked.join(', ')}`);

  // 3) 규칙에 등록되지 않은 임의의 다른 IP는 통과
  const other = await guardedDecide({ path: '/notes' }, { sourceIp: '192.0.2.250', ...ctx(T0 + 60_000) });
  assert.equal(other, allow);

  // 4) 만료 시각이 되면 공격 출발지도 XDR 규칙 때문에 막히지 않는다.
  for (const ip of attackIps) {
    const after = await guardedDecide({ path: '/notes' }, { sourceIp: ip, ...ctx(T0 + RULE_TTL_MS) });
    assert.equal(after, allow, `${ip}: 만료 후에도 막힘`);
  }
  console.log(`    · 종단: 요청 ${alerts.length}건 중 거부 ${deniedCount}건(공격 출발지 ${attackIps.size}곳), 정상/애매 출발지 오차단 0건, 만료 후 전부 통과`);
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
