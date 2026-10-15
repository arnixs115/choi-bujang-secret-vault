import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(SCRIPT_DIR, '..');

// 실제 사전 침해 검증본이 확인되기 전까지는 기본 경로만 지정한다.
// 이 파일을 임의로 생성하거나 과거 커밋을 백업으로 간주하지 않는다.
const BACKUP_PATH = path.join(
  PROJECT_ROOT,
  'policy-backups',
  'verified-policy.json',
);

// 중요: 백업과 독립적으로 사전에 확립된 신뢰 기준이 아직 없다.
// 검증된 기준을 확인하기 전에는 이 값을 임의로 채우지 않는다.
const TRUSTED_BACKUP_SHA256 = null;

const BACKUP_FORMAT = 'aleph.policy-backup.v1';
const SUPPORTED_POLICY_VERSIONS = new Set(['aleph.policy.v1']);
const VERIFIED_PROVENANCE = 'verified-pre-incident-backup';
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const POLICY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function abort(message) {
  throw new Error(message);
}


function parseCurrentRuleIds(source) {
  const match = source.match(
    /export\s+const\s+RULE_IDS\s*=\s*Object\.freeze\(\s*(\[[\s\S]*?\])\s*\)\s*;/u,
  );

  if (!match) {
    abort('현재 정책의 RULE_IDS 선언을 찾을 수 없습니다.');
  }

  const literal = match[1];

  // 문자열 ID와 쉼표만 포함된 배열 리터럴인지 먼저 확인한다.
  const stringPattern = /'([^'\\]*)'|"([^"\\]*)"/gu;
  const ids = [...literal.matchAll(stringPattern)].map(
    entry => entry[1] ?? entry[2],
  );

  const residue = literal
    .replace(stringPattern, '')
    .replace(/[\s,[\]]/gu, '');

  if (residue.length > 0) {
    abort('현재 정책의 RULE_IDS 형식이 올바르지 않습니다.');
  }

  if (
    ids.length === 0 ||
    ids.some(id => !id.trim()) ||
    new Set(ids).size !== ids.length
  ) {
    abort('현재 정책의 RULE_IDS 내용이 올바르지 않습니다.');
  }

  return ids;
}


function extractBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);

  if (start < 0) {
    abort(`현재 정책에서 규칙 경계를 찾을 수 없습니다: ${startMarker}`);
  }

  const end = source.indexOf(endMarker, start + startMarker.length);

  if (end < 0 || end <= start) {
    abort(`현재 정책의 규칙 종료 경계를 찾을 수 없습니다: ${endMarker}`);
  }

  return source.slice(start, end).trim();
}

function getCurrentRuleFingerprints(source, ruleIds) {
  // 이 매핑은 현재 src/decider.mjs의 구조에 맞춘 것이다.
  // 정책 파일의 함수 경계가 달라지면 조용히 추정하지 않고 중단한다.
  const segments = {
    'starter.deny': extractBetween(
      source,
      'function validRequestShape',
      'function resourceZoneAllows',
    ),

    device_registered: extractBetween(
      source,
      '// 기존 6단계: 등록되지 않은 기기는 거부',
      '// 구역 정책을 통과하지 못하면',
    ),

    resource_zone_policy: extractBetween(
      'function resourceZoneAllows' === 'function resourceZoneAllows'
        ? source
        : '',
      'function resourceZoneAllows',
      'function decisionResponse',
    ),

    step_up_required: extractBetween(
      source,
      '// 기존 7단계: 복합 이상 접속 탐지',
      '\n  return decisionResponse(\n    request,\n    \'allow\',\n    \'approved\',',
    ),
  };

  const fingerprints = {};

  for (const id of ruleIds) {
    const segment = segments[id];

    if (typeof segment !== 'string' || segment.length === 0) {
      abort(`비교를 지원하지 않는 현재 정책 규칙입니다: ${id}`);
    }

    fingerprints[id] = sha256(segment);
  }

  return fingerprints;
}

function validateBackup(backup) {
  if (!backup || typeof backup !== 'object' || Array.isArray(backup)) {
    abort('백업 형식이 올바르지 않습니다.');
  }

  if (backup.format !== BACKUP_FORMAT) {
    const SUPPORTED_POLICY_VERSIONS = new Set(['aleph.policy.v1']);
    abort('지원하지 않는 백업 형식 또는 정책 버전입니다.');
  }

  if (
    typeof backup.policyVersion !== 'string' ||
    !POLICY_VERSION_PATTERN.test(backup.policyVersion)
  ) {
    abort('백업의 정책 버전이 올바르지 않습니다.');
  }

  if (
    typeof backup.sourceCommit !== 'string' ||
    !/^[a-f0-9]{40}$/u.test(backup.sourceCommit)
  ) {
    abort('백업의 출처 커밋 정보가 올바르지 않습니다.');
  }

  if (backup.provenance !== VERIFIED_PROVENANCE) {
    abort('사전 침해 검증본이라는 출처 정보가 확인되지 않습니다.');
  }

  if (!Array.isArray(backup.rules) || backup.rules.length === 0) {
    abort('백업의 규칙 목록이 없거나 비어 있습니다.');
  }

  if (
    typeof backup.policyVersion !== 'string' ||
    !POLICY_VERSION_PATTERN.test(backup.policyVersion)
  ) {
    abort('백업의 정책 버전이 올바르지 않습니다.');
  }

  if (!SUPPORTED_POLICY_VERSIONS.has(backup.policyVersion)) {
    abort(`지원하지 않는 정책 버전입니다: ${backup.policyVersion}`);
  }

  const seen = new Set();

  for (const rule of backup.rules) {
    if (
      !rule ||
      typeof rule !== 'object' ||
      typeof rule.id !== 'string' ||
      !rule.id.trim() ||
      typeof rule.fingerprint !== 'string' ||
      !SHA256_PATTERN.test(rule.fingerprint)
    ) {
      abort('백업의 규칙 형식이 올바르지 않습니다.');
    }

    if (seen.has(rule.id)) {
      abort(`백업에 중복된 규칙 ID가 있습니다: ${rule.id}`);
    }

    seen.add(rule.id);
  }

  return Object.fromEntries(
    backup.rules.map(rule => [rule.id, rule.fingerprint]),
  );
}

/**
 * 비교만 수행한다.
 * 테스트에서는 임시 파일과 테스트 전용 신뢰 해시를 전달할 수 있지만,
 * CLI 실행은 아래의 고정된 설정을 사용한다.
 */
export async function comparePolicyBackup({
  backupPath = BACKUP_PATH,
  currentPolicyPath = path.join(PROJECT_ROOT, 'src', 'decider.mjs'),
  trustedBackupSha256 = TRUSTED_BACKUP_SHA256,
} = {}) {
  let backupBytes;

  try {
    backupBytes = await readFile(backupPath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      abort(
        `검증된 백업이 없습니다: ${backupPath}\n` +
        '과거 커밋이나 현재 정책을 백업으로 대신하지 않습니다.',
      );
    }

    throw error;
  }

  if (
    typeof trustedBackupSha256 !== 'string' ||
    !SHA256_PATTERN.test(trustedBackupSha256)
  ) {
    abort(
      '사전에 확립된 백업 무결성 기준이 없습니다. ' +
      '신뢰 기준이 마련될 때까지 비교를 중단합니다.',
    );
  }

  const actualHash = sha256(backupBytes);

  if (actualHash !== trustedBackupSha256) {
    abort('백업 SHA-256이 사전 무결성 기준과 일치하지 않습니다.');
  }

  let backup;

  try {
    backup = JSON.parse(backupBytes.toString('utf8'));
  } catch {
    abort('백업이 올바른 JSON 형식이 아닙니다.');
  }

  const backupRules = validateBackup(backup);

  let currentSource;

  try {
    currentSource = await readFile(currentPolicyPath, 'utf8');
  } catch {
    abort('현재 정책 파일을 읽을 수 없습니다.');
  }

  const currentIds = parseCurrentRuleIds(currentSource);
  const currentRules = getCurrentRuleFingerprints(
    currentSource,
    currentIds,
  );

  const added = [];
  const deleted = [];
  const changed = [];

  for (const [id, fingerprint] of Object.entries(currentRules)) {
    if (!(id in backupRules)) {
      added.push(id);
    } else if (backupRules[id] !== fingerprint) {
      changed.push(id);
    }
  }

  for (const id of Object.keys(backupRules)) {
    if (!(id in currentRules)) {
      deleted.push(id);
    }
  }

  return {
    backupVersion: backup.policyVersion,
    backupSourceCommit: backup.sourceCommit,
    currentVersion: `source-sha256:${sha256(currentSource)}`,
    added,
    deleted,
    changed,
  };
}

async function main() {
  try {
    const result = await comparePolicyBackup();

    console.log('정책 백업 검증 및 비교 완료');
    console.log(`백업 정책 버전: ${result.backupVersion}`);
    console.log(`백업 출처 커밋: ${result.backupSourceCommit}`);
    console.log(`현재 정책 지문: ${result.currentVersion}`);
    console.log(`추가된 규칙: ${result.added.join(', ') || '(없음)'}`);
    console.log(`삭제된 규칙: ${result.deleted.join(', ') || '(없음)'}`);
    console.log(`변경된 규칙: ${result.changed.join(', ') || '(없음)'}`);
  } catch (error) {
    console.error(`정책 비교 중단: ${error.message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  await main();
}
