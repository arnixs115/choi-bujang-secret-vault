
import { appendFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LOG_PATH = join(MODULE_DIR, '..', 'alerts.log');

const BLOCK_THRESHOLD = 0.85;
const RULE_TTL_MS = 15 * 60 * 1000; // 15분

function isValidAlertId(value) {
  return typeof value === 'string' &&
    /^[A-Za-z0-9._:-]{1,80}$/.test(value);
}

function isValidIPv4(value) {
  if (typeof value !== 'string') return false;

  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 &&
      number <= 255 &&
      String(number) === part;
  });
}

function hasClearBruteForceEvidence(alert) {
  const description = String(alert?.rule?.description ?? '');
  const mitre = Array.isArray(alert?.rule?.mitre)
    ? alert.rule.mitre
    : [];

  if (!mitre.includes('T1110')) return false;

  const count = Number(alert?.data?.count);
  const match = description.match(
    /(?:로그인\s*)?실패\s*(\d+)\s*건/,
  );

  const failureCount =
    Number.isFinite(count) && count > 0
      ? count
      : Number(match?.[1] ?? 0);

  const shortWindow =
    /\d+\s*(?:초|분)\s*(?:안|동안|이내)/.test(description);

  const repeatedFailures =
    failureCount >= 20 && shortWindow;

  const passwordSpraying =
    /(?:여러 계정|서로 다른 계정|계정\s*\d+개|계정 이름을 바꿔 가며)/
      .test(description) &&
    /(?:같은|동일한|소수의) 비밀번호/.test(description) &&
    /실패|넣었습니다|시도했습니다/.test(description);

  return repeatedFailures || passwordSpraying;
}

function oneLine(value, maxLength = 240) {
  return String(value ?? '')
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .slice(0, maxLength);
}

/**
 * addDenyRule은 ZTNA 연결부에서 제공하는 함수다.
 * 이 모듈은 src/decider.mjs나 기존 판정 규칙을 수정하지 않는다.
 */
export async function respond({
  alert,
  decision,
  addDenyRule,
  now = () => new Date(),
  logPath = DEFAULT_LOG_PATH,
}) {
  const alertId = isValidAlertId(alert?.id)
    ? alert.id
    : null;

  const sourceAddress = alert?.data?.srcip;

  const eligible =
    decision?.action === 'block' &&
    typeof decision.confidence === 'number' &&
    Number.isFinite(decision.confidence) &&
    decision.confidence >= BLOCK_THRESHOLD &&
    alertId !== null &&
    isValidIPv4(sourceAddress) &&
    hasClearBruteForceEvidence(alert);

  let ruleAdded = false;
  let ruleStatus = 'not_eligible';
  let expiresAt = null;

  if (eligible) {
    if (typeof addDenyRule !== 'function') {
      ruleStatus = 'adapter_missing';
    } else {
      const currentTime = now();
      const currentDate = currentTime instanceof Date
        ? currentTime
        : new Date(currentTime);

      if (!Number.isFinite(currentDate.getTime())) {
        throw new TypeError('invalid_response_clock');
      }

      expiresAt = new Date(
        currentDate.getTime() + RULE_TTL_MS,
      ).toISOString();

      const rule = {
        id: `xdr.brute-force.${alertId}`,
        effect: 'deny',
        sourceAddress,
        expiresAt,
        evidenceAlertId: alertId,
        reason: oneLine(
          decision.reason || '명확한 무차별 대입 패턴',
        ),
      };

      try {
        await addDenyRule(rule);
        ruleAdded = true;
        ruleStatus = 'added';
      } catch {
        ruleStatus = 'failed';
      }
    }
  }

  const action = ['block', 'alert', 'record'].includes(
    decision?.action,
  )
    ? decision.action
    : 'record';

  const confidence =
    typeof decision?.confidence === 'number' &&
    Number.isFinite(decision.confidence)
      ? Math.min(1, Math.max(0, decision.confidence))
      : 0;

  const logEntry = {
    timestamp: new Date().toISOString(),
    moduleKey: 'brute-force',
    alertId,
    action,
    confidence,
    reason: oneLine(decision?.reason || '판정 근거 없음'),
    ruleStatus,
    ruleId: ruleAdded
      ? `xdr.brute-force.${alertId}`
      : null,
    expiresAt: ruleAdded ? expiresAt : null,
  };

  await appendFile(
    logPath,
    `${JSON.stringify(logEntry)}\n`,
    'utf8',
  );

  return {
    action,
    ruleAdded,
    ruleStatus,
    expiresAt: ruleAdded ? expiresAt : null,
  };
}
