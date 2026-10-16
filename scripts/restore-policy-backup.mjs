import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);

const BACKUP_PATH = path.join(
  ROOT,
  'policy-backups',
  'verified-policy.json',
);

const POLICY_PATH = path.join(ROOT, 'src', 'decider.mjs');

// 독립적으로 검증한 백업 해시가 없으므로 실제 복구는 기본적으로 중단한다.
const TRUSTED_BACKUP_SHA256 = null;

const FORMAT = 'aleph.policy-restore.v1';
const POLICY_VERSION = 'aleph.policy.v1';
const PROVENANCE = 'verified-pre-incident-backup';

// 이번 복구 대상은 구역 정책 함수 하나로 제한한다.
const START_MARKER = 'function resourceZoneAllows';
const END_MARKER = 'function decisionResponse';

function abort(message) {
  throw new Error(message);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function extractSection(source) {
  const start = source.indexOf(START_MARKER);

  if (start < 0) {
    abort('정책 시작 경계를 찾을 수 없습니다.');
  }

  const end = source.indexOf(END_MARKER, start + START_MARKER.length);

  if (end < 0 || end <= start) {
    abort('정책 종료 경계를 찾을 수 없습니다.');
  }

  return {
    start,
    end,
    text: source.slice(start, end),
  };
}

function validateBackup(backup) {
  if (!backup || typeof backup !== 'object' || Array.isArray(backup)) {
    abort('백업 JSON 형식이 올바르지 않습니다.');
  }

  if (backup.format !== FORMAT) {
    abort('지원하지 않는 복구 백업 형식입니다.');
  }

  if (backup.policyVersion !== POLICY_VERSION) {
    abort('지원하지 않는 정책 버전입니다.');
  }

  if (backup.provenance !== PROVENANCE) {
    abort('사전 침해 검증본의 출처가 확인되지 않습니다.');
  }

  if (
    typeof backup.sourceCommit !== 'string' ||
    !/^[a-f0-9]{40}$/u.test(backup.sourceCommit)
  ) {
    abort('백업의 출처 커밋 정보가 올바르지 않습니다.');
  }

  if (
    typeof backup.policySource !== 'string' ||
    backup.policySource.trim().length === 0
  ) {
    abort('복구할 정책 원문이 없습니다. 지문만으로는 복구할 수 없습니다.');
  }

  extractSection(backup.policySource);
}

export async function restorePolicyBackup({
  backupPath = BACKUP_PATH,
  currentPolicyPath = POLICY_PATH,
  trustedBackupSha256 = TRUSTED_BACKUP_SHA256,
  apply = false,
  confirm = false,
} = {}) {
  let backupBytes;

  try {
    backupBytes = await readFile(backupPath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      abort(`검증된 정책 백업이 없습니다: ${backupPath}`);
    }

    throw error;
  }

  if (
    typeof trustedBackupSha256 !== 'string' ||
    !/^[a-f0-9]{64}$/u.test(trustedBackupSha256)
  ) {
    abort('사전에 확립된 백업 SHA-256 기준이 없습니다.');
  }

  if (sha256(backupBytes) !== trustedBackupSha256) {
    abort('백업 SHA-256이 사전 무결성 기준과 일치하지 않습니다.');
  }

  let backup;

  try {
    backup = JSON.parse(backupBytes.toString('utf8'));
  } catch {
    abort('백업이 올바른 JSON 형식이 아닙니다.');
  }

  validateBackup(backup);

  let currentSource;

  try {
    currentSource = await readFile(currentPolicyPath, 'utf8');
  } catch {
    abort('현재 정책 파일을 읽을 수 없습니다.');
  }

  const current = extractSection(currentSource);
  const backedUp = extractSection(backup.policySource);

  const preview = {
    target: 'resource_zone_policy',
    sourceCommit: backup.sourceCommit,
    changed: current.text !== backedUp.text,
    beforeSha256: sha256(current.text),
    afterSha256: sha256(backedUp.text),
    filesToChange: [path.relative(ROOT, currentPolicyPath)],
    filesToPreserve: [
      'src/decider.mjs의 다른 규칙',
      'api/notes.js',
      'api/notes/[id].js',
      '감사 이력 파일',
    ],
    applied: false,
  };

  // 기본 동작은 미리보기이며 파일을 수정하지 않는다.
  if (!apply) return preview;

  if (!confirm) {
    abort('실제 복구에는 --apply와 --confirm이 모두 필요합니다.');
  }

  if (!preview.changed) {
    return preview;
  }

  const restoredSource =
    currentSource.slice(0, current.start) +
    backedUp.text +
    currentSource.slice(current.end);

  // 교체 후 대상 함수 바깥의 코드가 동일한지 재검사한다.
  const restored = extractSection(restoredSource);

  const outsideBefore =
    currentSource.slice(0, current.start) +
    currentSource.slice(current.end);

  const outsideAfter =
    restoredSource.slice(0, restored.start) +
    restoredSource.slice(restored.end);

  if (outsideBefore !== outsideAfter) {
    abort('대상 규칙 밖의 내용이 달라져 복구를 중단합니다.');
  }

  // 감사 이력은 읽거나 수정하지 않는다.
  await writeFile(currentPolicyPath, restoredSource, 'utf8');

  return { ...preview, applied: true };
}

async function main() {
  const flags = new Set(process.argv.slice(2));

  if ([...flags].some(
    flag => !['--apply', '--confirm'].includes(flag),
  )) {
    console.error(
      '사용법: node scripts/restore-policy-backup.mjs [--apply --confirm]',
    );
    process.exitCode = 2;
    return;
  }

  try {
    const result = await restorePolicyBackup({
      apply: flags.has('--apply'),
      confirm: flags.has('--confirm'),
    });

    console.log('정책 복구 사전 확인');
    console.log(`대상 규칙: ${result.target}`);
    console.log(`백업 출처 커밋: ${result.sourceCommit}`);
    console.log(`변경 예정: ${result.changed ? '예' : '아니요'}`);
    console.log(`현재 지문: ${result.beforeSha256}`);
    console.log(`복구 지문: ${result.afterSha256}`);
    console.log(`수정 파일: ${result.filesToChange.join(', ')}`);
    console.log(`보존 대상: ${result.filesToPreserve.join(', ')}`);
    console.log(`실제 복구: ${result.applied ? '완료' : '미실행'}`);
  } catch (error) {
    console.error(`정책 복구 중단: ${error.message}`);
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}