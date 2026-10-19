
import { appendFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LOG_PATH = join(MODULE_DIR, '..', 'alerts.log');

const BLOCK_THRESHOLD = 0.85;
const RULE_TTL_MS = 15 * 60 * 1000;

const PATTERN_NAMES = new Set([
  'unsigned_new_service',
  'unusual_scheduled_task',
  'startup_folder_change',
]);

function isValidAlertId(value) {
  return (
    typeof value === 'string' &&
    /^[A-Za-z0-9._:-]{1,80}$/u.test(value)
  );
}

function isValidIPv4(value) {
  if (typeof value !== 'string') return false;

  const parts = value.split('.');
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d{1,3}$/u.test(part)) return false;
    const number = Number(part);
    return number >= 0 &&
      number <= 255 &&
      String(number) === part;
  });
}

function hasPersistenceEvidence(alert, reason) {
  const description = String(
    alert?.rule?.description ?? '',
  );
  const mitre = Array.isArray(alert?.rule?.mitre)
    ? alert.rule.mitre
    : [];

  if (!PATTERN_NAMES.has(reason)) return false;

  if (reason === 'unsigned_new_service') {
    return (
      mitre.includes('T1543') &&
      /서비스/u.test(description) &&
      /새 서비스|서비스 등록|서비스 실행 파일이 바뀌|서비스가 변경/u.test(
        description,
      ) &&
      /서명(?:이|은)?\s*없|서명되지 않/u.test(description)
    );
  }

  if (reason === 'unusual_scheduled_task') {
    const directMatch =
      mitre.includes('T1053') &&
      /예약 작업/u.test(description) &&
      /낯선|처음 보는|임의 문자열/u.test(description) &&
      /임시 폴더/u.test(description);

    const combinedMatch =
      mitre.includes('T1053') &&
      mitre.includes('T1543') &&
      /시작 프로그램과 예약 작업/u.test(description) &&
      /같은 임시 파일/u.test(description);

    return directMatch || combinedMatch;
  }

  if (reason === 'startup_folder_change') {
    return (
      mitre.includes('T1543') &&
      /시작 폴더|시작 프로그램|시작 항목/u.test(description) &&
      /추가됐|알 수 없|평소 목록에 없/u.test(description)
    );
  }

  return false;
}

function oneLine(value, maxLength = 240) {
  return String(value ?? '')
    .replace(/[\r\n\u2028\u2029]+/gu, ' ')
    .slice(0, maxLength);
}

/**
 * addDenyRule은 호출자가 제공하는 ZTNA 연결 콜백이다.
 * 기존 src/decider.mjs의 규칙은 변경하지 않는다.
 */
export async function respond({
  alert,
  decision,
  addDenyRule,
  now = () => new Date(),
  logPath = DEFAULT_LOG_PATH,
}) {
  const currentTime = now();
  const currentDate = currentTime instanceof Date
    ? currentTime
    : new Date(currentTime);

  if (!Number.isFinite(currentDate.getTime())) {
    throw new TypeError('invalid_response_clock');
  }

  const alertId = isValidAlertId(alert?.id)
    ? alert.id
    : null;

  const sourceAddress = alert?.data?.srcip;
  const reason = oneLine(decision?.reason || '판정 근거 없음');

  const eligible =
    decision?.action === 'block' &&
    typeof decision.confidence === 'number' &&
    Number.isFinite(decision.confidence) &&
    decision.confidence >= BLOCK_THRESHOLD &&
    alertId !== null &&
    isValidIPv4(sourceAddress) &&
    hasPersistenceEvidence(alert, decision.reason);

  let ruleAdded = false;
  let ruleStatus = 'not_eligible';
  let expiresAt = null;

  if (eligible) {
    if (typeof addDenyRule !== 'function') {
      ruleStatus = 'adapter_missing';
    } else {
      expiresAt = new Date(
        currentDate.getTime() + RULE_TTL_MS,
      ).toISOString();

      const rule = {
        id: `xdr.persistence.${alertId}`,
        effect: 'deny',
        sourceAddress,
        expiresAt,
        evidenceAlertId: alertId,
        reason,
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

  const rawConfidence = decision?.confidence;
  const confidence =
    typeof rawConfidence === 'number' &&
    Number.isFinite(rawConfidence)
      ? Math.min(1, Math.max(0, rawConfidence))
      : 0;

  const logEntry = {
    timestamp: currentDate.toISOString(),
    moduleKey: 'persistence',
    alertId,
    action,
    confidence,
    reason,
    ruleStatus,
    ruleId: ruleAdded
      ? `xdr.persistence.${alertId}`
      : null,
    expiresAt: ruleAdded ? expiresAt : null,
  };

  // appendFile로 기존 기록을 덮어쓰지 않고 한 줄 추가한다.
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
