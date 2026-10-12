import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { respond } from '../xdr/brute-force/respond.mjs';

const tempDir = await mkdtemp(join(tmpdir(), 'brute-force-test-'));
const logPath = join(tempDir, 'alerts.log');
const registeredRules = [];

try {
  const attackAlert = {
    id: 'bf-test-01',
    rule: {
      description: '같은 주소에서 2분 안에 로그인 실패 48건이 쌓였습니다.',
      mitre: ['T1110'],
    },
    data: {
      srcip: '203.0.113.10',
      count: '48',
    },
  };

  const attackDecision = {
    action: 'block',
    confidence: 0.96,
    reason: '반복 로그인 실패',
  };

  const attackResult = await respond({
    alert: attackAlert,
    decision: attackDecision,
    addDenyRule: async (rule) => registeredRules.push(rule),
    now: () => new Date('2026-10-12T12:00:00.000Z'),
    logPath,
  });

  assert.equal(attackResult.ruleAdded, true);
  assert.equal(registeredRules.length, 1);
  assert.equal(registeredRules[0].effect, 'deny');
  assert.equal(registeredRules[0].evidenceAlertId, 'bf-test-01');
  assert.equal(
    registeredRules[0].expiresAt,
    '2026-10-12T12:15:00.000Z',
  );

  const normalAlert = {
    id: 'bf-test-02',
    rule: {
      description: '로그인이 성공했습니다.',
      mitre: [],
    },
    data: {
      srcip: '192.0.2.60',
    },
  };

  const normalResult = await respond({
    alert: normalAlert,
    decision: {
      action: 'record',
      confidence: 0.05,
      reason: '일반 이벤트',
    },
    addDenyRule: async (rule) => registeredRules.push(rule),
    now: () => new Date('2026-10-12T12:00:00.000Z'),
    logPath,
  });

  assert.equal(normalResult.ruleAdded, false);
  assert.equal(registeredRules.length, 1);

  const logLines = (await readFile(logPath, 'utf8'))
    .trim()
    .split('\n');

  assert.equal(logLines.length, 2);
  assert.equal(JSON.parse(logLines[0]).alertId, 'bf-test-01');
  assert.equal(JSON.parse(logLines[1]).alertId, 'bf-test-02');

  console.log('PASS: 명확한 공격 후보에 만료 규칙 등록');
  console.log('PASS: 정상 이벤트는 규칙 등록에서 제외');
  console.log('PASS: 두 경보 모두 로그 기록');
} finally {
  await rm(tempDir, { recursive: true, force: true });
}