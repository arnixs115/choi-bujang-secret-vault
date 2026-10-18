// 사용: node scripts/xdr-web-injection-respond.mjs
// xdr/fixtures/web-injection.json 의 경보를 decide → respond 로 흘려보낸다.
// 결과: xdr/web-injection/deny-rules.json(규칙), xdr/alerts.log(JSONL, 실행할 때마다 누적)
import { readFile } from 'node:fs/promises';
import * as decideMod from '../xdr/web-injection/decide.mjs';
import { respond } from '../xdr/web-injection/respond.mjs';

const decide = decideMod.decide ?? decideMod.default;
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'));
const alerts = Array.isArray(fixture) ? fixture : (fixture.alerts ?? fixture.events ?? fixture.items);
if (!Array.isArray(alerts)) throw new Error('fixture에서 경보 배열을 찾지 못했습니다.');

const counts = { registered: 0, duplicate: 0, skipped: 0, failed: 0, logFailed: 0 };
for (const alert of alerts) {
  const decision = await decide(alert);
  const r = await respond(alert, decision);
  counts[r.rule.status] += 1;
  if (!r.log.ok) counts.logFailed += 1;
  const why = r.rule.skipReason ?? r.rule.errorKind ?? '';
  console.log(`${String(r.alertId).padEnd(8)} ${String(r.action).padEnd(7)} ${r.confidence}  → ${r.rule.status} ${why}`);
}
console.log(counts);
console.log('이 결과는 규칙 파일과 알림 로그를 만든 것입니다. 실제 ZTNA 엔진이 이 규칙을 읽어 집행하는지는 별도로 확인해야 합니다.');
process.exitCode = counts.failed || counts.logFailed ? 1 : 0;
