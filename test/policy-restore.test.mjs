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

import {
  restorePolicyBackup,
} from '../scripts/restore-policy-backup.mjs';

const tempDirs = [];

const currentPolicy = `
function starterRule() {
  return 'starter unchanged';
}

function resourceZoneAllows(request) {
  return request.path.startsWith('/notes');
}

function decisionResponse() {
  return 'response unchanged';
}

function stepUpRule() {
  return 'step-up unchanged';
}
`;

const backupPolicy = `
function starterRule() {
  return 'starter unchanged';
}

function resourceZoneAllows(request) {
  return request.method === 'GET' &&
    /^\\/notes\\/[^/?#]+$/u.test(request.path);
}

function decisionResponse() {
  return 'response unchanged';
}

function stepUpRule() {
  return 'step-up unchanged';
}
`;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function createFixture() {
  const dir = await mkdtemp(
    path.join(os.tmpdir(), 'policy-restore-test-'),
  );

  tempDirs.push(dir);

  const currentPolicyPath = path.join(dir, 'decider.mjs');
  const backupPath = path.join(dir, 'backup.json');
  const auditPath = path.join(dir, 'audit.log');

  await writeFile(currentPolicyPath, currentPolicy);
  await writeFile(auditPath, 'existing audit history\n');

  const backup = {
    format: 'aleph.policy-restore.v1',
    policyVersion: 'aleph.policy.v1',
    provenance: 'verified-pre-incident-backup',
    sourceCommit: 'b'.repeat(40),
    targetRule: 'resource_zone_policy',
    policySource: backupPolicy,
  };

  await writeFile(backupPath, JSON.stringify(backup));

  return {
    dir,
    currentPolicyPath,
    backupPath,
    auditPath,
  };
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((dir) =>
      rm(dir, { recursive: true, force: true }),
    ),
  );
});

test('백업 파일이 없으면 복구를 중단한다', async () => {
  const fixture = await createFixture();

  await assert.rejects(
    restorePolicyBackup({
      ...fixture,
      backupPath: path.join(fixture.dir, 'missing.json'),
      trustedBackupSha256: 'a'.repeat(64),
    }),
    /검증된 정책 백업이 없습니다/u,
  );
});

test('신뢰할 수 있는 해시 기준이 없으면 복구를 중단한다', async () => {
  const fixture = await createFixture();

  await assert.rejects(
    restorePolicyBackup({
      ...fixture,
      trustedBackupSha256: null,
    }),
    /사전에 확립된 백업 SHA-256 기준이 없습니다/u,
  );
});

test('해시가 일치하지 않으면 현재 정책을 변경하지 않는다', async () => {
  const fixture = await createFixture();

  await assert.rejects(
    restorePolicyBackup({
      ...fixture,
      trustedBackupSha256: '0'.repeat(64),
      apply: true,
      confirm: true,
    }),
    /SHA-256이 사전 무결성 기준과 일치하지 않습니다/u,
  );

  assert.equal(
    await readFile(fixture.currentPolicyPath, 'utf8'),
    currentPolicy,
  );
});

test('미리보기는 변경 대상을 보여 주고 파일은 수정하지 않는다', async () => {
  const fixture = await createFixture();
  const backupBytes = await readFile(fixture.backupPath);

  const result = await restorePolicyBackup({
    ...fixture,
    trustedBackupSha256: sha256(backupBytes),
  });

  assert.equal(result.target, 'resource_zone_policy');
  assert.equal(result.changed, true);
  assert.equal(result.applied, false);

  assert.equal(
    await readFile(fixture.currentPolicyPath, 'utf8'),
    currentPolicy,
  );
});

test('명시적 확인이 없으면 실제 복구를 실행하지 않는다', async () => {
  const fixture = await createFixture();
  const backupBytes = await readFile(fixture.backupPath);

  await assert.rejects(
    restorePolicyBackup({
      ...fixture,
      trustedBackupSha256: sha256(backupBytes),
      apply: true,
      confirm: false,
    }),
    /실제 복구에는 --apply와 --confirm이 모두 필요합니다/u,
  );

  assert.equal(
    await readFile(fixture.currentPolicyPath, 'utf8'),
    currentPolicy,
  );
});

test('확인된 복구는 대상 규칙만 바꾸고 다른 코드와 감사 이력을 보존한다', async () => {
  const fixture = await createFixture();
  const backupBytes = await readFile(fixture.backupPath);

  const result = await restorePolicyBackup({
    ...fixture,
    trustedBackupSha256: sha256(backupBytes),
    apply: true,
    confirm: true,
  });

  const restored = await readFile(
    fixture.currentPolicyPath,
    'utf8',
  );

  assert.equal(result.applied, true);
  assert.match(restored, /request\.method === 'GET'/u);
  assert.match(restored, /starter unchanged/u);
  assert.match(restored, /response unchanged/u);
  assert.match(restored, /step-up unchanged/u);

  assert.equal(
    await readFile(fixture.auditPath, 'utf8'),
    'existing audit history\n',
  );
});