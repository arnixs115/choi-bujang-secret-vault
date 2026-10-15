import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';

import { comparePolicyBackup } from '../scripts/compare-policy-backup.mjs';

const temporaryDirectories = [];

const BACKUP_FORMAT = 'aleph.policy-backup.v1';
const POLICY_VERSION = 'aleph.policy.v1';
const VERIFIED_PROVENANCE = 'verified-pre-incident-backup';

const STEP_UP_END = `
  return decisionResponse(
    request,
    'allow',
    'approved',`;

const TEST_POLICY_SOURCE = `
export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
  'resource_zone_policy',
]);

function validRequestShape() {
  return true;
}

function validSignals() {
  return true;
}

function validRecentEvents() {
  return true;
}

function resourceZoneAllows() {
  return true;
}

function decisionResponse() {
  return true;
}

// 기존 6단계: 등록되지 않은 기기는 거부
if (request.deviceRegistered !== true) {
  return false;
}

// 구역 정책을 통과하지 못하면
// 기존 7단계: 복합 이상 접속 탐지
const testStepUpRule = true;${STEP_UP_END}
    ['step_up_required'],
  );
`;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fingerprintBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `시작 경계를 찾을 수 없음: ${startMarker}`);

  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(end, -1, `종료 경계를 찾을 수 없음: ${endMarker}`);

  return sha256(source.slice(start, end).trim());
}

function getTestRuleFingerprints(source) {
  return {
    'starter.deny': fingerprintBetween(
      source,
      'function validRequestShape',
      'function resourceZoneAllows',
    ),
    device_registered: fingerprintBetween(
      source,
      '// 기존 6단계: 등록되지 않은 기기는 거부',
      '// 구역 정책을 통과하지 못하면',
    ),
    resource_zone_policy: fingerprintBetween(
      source,
      'function resourceZoneAllows',
      'function decisionResponse',
    ),
    step_up_required: fingerprintBetween(
      source,
      '// 기존 7단계: 복합 이상 접속 탐지',
      STEP_UP_END,
    ),
  };
}

async function createFixture() {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), 'policy-backup-test-'),
  );
  temporaryDirectories.push(directory);

  const backupPath = path.join(directory, 'TEST-ONLY-backup.json');
  const currentPolicyPath = path.join(directory, 'TEST-ONLY-current.mjs');

  await writeFile(currentPolicyPath, TEST_POLICY_SOURCE, 'utf8');

  const fingerprints = getTestRuleFingerprints(TEST_POLICY_SOURCE);

  const backup = {
    format: BACKUP_FORMAT,
    policyVersion: POLICY_VERSION,
    provenance: VERIFIED_PROVENANCE,
    sourceCommit: 'a'.repeat(40),
    rules: Object.entries(fingerprints).map(([id, fingerprint]) => ({
      id,
      fingerprint,
    })),
  };

  return {
    backupPath,
    currentPolicyPath,
    backup,
  };
}

async function writeBackup(backupPath, backup) {
  await writeFile(backupPath, JSON.stringify(backup, null, 2), 'utf8');
}

async function getBackupHash(backupPath) {
  return sha256(await readFile(backupPath));
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(directory =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

test('백업 파일이 없으면 비교를 중단한다', async () => {
  const fixture = await createFixture();

  await assert.rejects(
    comparePolicyBackup({
      ...fixture,
      backupPath: path.join(path.dirname(fixture.backupPath), 'missing.json'),
      trustedBackupSha256: 'a'.repeat(64),
    }),
    /검증된 백업이 없습니다/u,
  );
});

test('사전 무결성 기준이 없으면 비교를 중단한다', async () => {
  const fixture = await createFixture();
  await writeBackup(fixture.backupPath, fixture.backup);

  await assert.rejects(
    comparePolicyBackup({
      ...fixture,
      trustedBackupSha256: null,
    }),
    /사전에 확립된 백업 무결성 기준이 없습니다/u,
  );
});

test('백업 해시가 무결성 기준과 다르면 중단한다', async () => {
  const fixture = await createFixture();
  await writeBackup(fixture.backupPath, fixture.backup);

  await assert.rejects(
    comparePolicyBackup({
      ...fixture,
      trustedBackupSha256: '0'.repeat(64),
    }),
    /SHA-256이 사전 무결성 기준과 일치하지 않습니다/u,
  );
});

test('백업 형식이 잘못되면 중단한다', async () => {
  const fixture = await createFixture();
  const invalidBackup = {
    ...fixture.backup,
    format: 'unsupported-format',
  };

  await writeBackup(fixture.backupPath, invalidBackup);

  await assert.rejects(
    comparePolicyBackup({
      ...fixture,
      trustedBackupSha256: await getBackupHash(fixture.backupPath),
    }),
    /지원하지 않는 백업 형식 또는 정책 버전입니다/u,
  );
});

test('지원하지 않는 정책 버전이면 중단한다', async () => {
  const fixture = await createFixture();
  const unsupportedBackup = {
    ...fixture.backup,
    policyVersion: 'aleph.policy.v99',
  };

  await writeBackup(fixture.backupPath, unsupportedBackup);

  await assert.rejects(
    comparePolicyBackup({
      ...fixture,
      trustedBackupSha256: await getBackupHash(fixture.backupPath),
    }),
    /지원하지 않는 정책 버전/u,
  );
});

test('테스트 전용 검증 사본의 추가·삭제·변경 규칙을 비교한다', async () => {
  const fixture = await createFixture();

  // 명시적인 TEST-ONLY 데이터다.
  // 실제 사전 침해 백업이나 운영 정책으로 사용하지 않는다.
  const testSnapshot = {
    ...fixture.backup,
    rules: [
      {
        id: 'starter.deny',
        fingerprint: 'f'.repeat(64),
      },
      {
        id: 'device_registered',
        fingerprint: fixture.backup.rules.find(
          rule => rule.id === 'device_registered',
        ).fingerprint,
      },
      {
        id: 'legacy_test_rule',
        fingerprint: 'e'.repeat(64),
      },
    ],
  };

  await writeBackup(fixture.backupPath, testSnapshot);

  const result = await comparePolicyBackup({
    ...fixture,
    trustedBackupSha256: await getBackupHash(fixture.backupPath),
  });

  assert.equal(result.backupVersion, POLICY_VERSION);
  assert.equal(result.backupSourceCommit, 'a'.repeat(40));

  assert.deepEqual(
    result.added,
    ['step_up_required', 'resource_zone_policy'],
  );
  assert.deepEqual(result.deleted, ['legacy_test_rule']);
  assert.deepEqual(result.changed, ['starter.deny']);
});