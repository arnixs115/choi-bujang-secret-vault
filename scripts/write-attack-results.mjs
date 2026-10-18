// 실제 배포에 점검기를 실행하고, 그 결과를 작전실 화면이 읽는 public/attack-results.json으로 씁니다.
// 요청은 src/attack-check.mjs가 보냅니다. 이 스크립트는 결과를 만들어 내거나 고치지 않고 그대로 저장합니다.
// 실행: npm run attack:results   (승인된 기기 세션 값은 ATTACK_CHECK_* 환경변수로 직접 넣을 때만 쓰이며 기록되지 않습니다)
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runAttackChecks } from '../src/attack-check.mjs';
import { summarizeAttackRecords, validateAttackRecords } from '../src/attack-record.mjs';

export const RESULTS_SCHEMA = 'aleph.attack-results.v1';

// 결과 파일의 내용. 기록은 검증을 통과한 것만 받고, generatedAt은 파일을 만든 시각이다.
export function buildAttackResults(records, generatedAt = new Date()) {
  const checked = validateAttackRecords(records);
  return {
    schema: RESULTS_SCHEMA,
    generatedAt: generatedAt.toISOString(),
    summary: summarizeAttackRecords(checked),
    records: checked,
  };
}

async function main() {
  const root = resolve(import.meta.dirname, '..');
  const config = JSON.parse(await readFile(join(root, 'aleph.config.json'), 'utf8'));
  const records = await runAttackChecks(config);
  const results = buildAttackResults(records);
  await mkdir(join(root, 'public'), { recursive: true });
  await writeFile(join(root, 'public', 'attack-results.json'), `${JSON.stringify(results, null, 2)}\n`, 'utf8');
  const s = results.summary;
  process.stdout.write(`public/attack-results.json 생성: 시험 ${s.total}개 · 실측 ${s.measured}개(통과 ${s.pass} · 실패 ${s.fail}) · 미실행 ${s.not_run} · 미확인 ${s.unverified}\n`
    + '미실행·미확인은 요청을 보내지 않았으므로 성공으로 세지 않았습니다. 결과를 확인한 뒤 이 파일을 커밋하고 다시 배포하세요.\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`점검 결과 파일 생성 중 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  });
}
