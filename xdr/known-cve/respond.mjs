import { appendFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_KEY = 'known-cve';
const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_LOG_PATH = join(MODULE_DIR, '..', 'alerts.log'); // xdr/alerts.log

const BLOCK_THRESHOLD = 0.85;
const RULE_TTL_MS = 15 * 60 * 1000; // 15분

// decide.mjs 의 log4j-jndi-lookup 조건과 같은 기준이다.
// decision 값만 믿고 차단하지 않도록, 경보 필드에서 근거를 한 번 더 확인한다.
// (rule.mitre 의 T1190, rule.level, rule.description 은 근거로 쓰지 않는다.)
const EVIDENCE_FIELDS = ['useragent', 'url'];
const FULL_LOOKUP = /\$\{jndi:(?:ldaps|ldap|rmi|dns):\/\//i;

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

// 자기 자신·전체를 막게 되는 주소는 규칙 대상으로 쓰지 않는다.
function isBlockableAddress(value) {
  if (!isValidIPv4(value)) return false;
  if (value === '0.0.0.0' || value === '255.255.255.255') return false;
  if (value.startsWith('127.')) return false;
  return true;
}

function safeDecode(value) {
  let current = value;
  for (let i = 0; i < 2; i += 1) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

function hasCompleteJndiLookup(alert) {
  const data = alert?.data;
  if (!data || typeof data !== 'object') return false;

  return EVIDENCE_FIELDS.some((name) => {
    const raw = data[name];
    if (typeof raw !== 'string' || raw === '') return false;
    return FULL_LOOKUP.test(raw) || FULL_LOOKUP.test(safeDecode(raw));
  });
}

function oneLine(value, maxLength = 240) {
  return String(value ?? '')
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .slice(0, maxLength);
}

/**
 * addDenyRule 은 ZTNA 연결부에서 제공하는 함수다.
 * 이 모듈은 src/decider.mjs 나 기존 판정 규칙을 수정하지 않는다.
 * 규칙은 decision 이 block(확신도 0.85 이상)이고, 경보 필드에서 완전한
 * JNDI 원격 조회 구문이 다시 확인될 때만 만든다. alert/record 는 규칙을 만들지 않는다.
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
    isBlockableAddress(sourceAddress) &&
    hasCompleteJndiLookup(alert);

  let ruleAdded = false;
  let ruleStatus = 'not_eligible';
  let expiresAt = null;

  const clock = now();
  const currentDate = clock instanceof Date ? clock : new Date(clock);
  const clockValid = Number.isFinite(currentDate.getTime());

  if (eligible) {
    if (typeof addDenyRule !== 'function') {
      ruleStatus = 'adapter_missing';
    } else {
      if (!clockValid) {
        throw new TypeError('invalid_response_clock');
      }

      expiresAt = new Date(
        currentDate.getTime() + RULE_TTL_MS,
      ).toISOString();

      const rule = {
        id: `xdr.${MODULE_KEY}.${alertId}`,
        effect: 'deny',
        sourceAddress,
        expiresAt,
        evidenceAlertId: alertId,
        reason: oneLine(
          decision.reason || '명확한 알려진 CVE 악용 패턴',
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
    timestamp: (clockValid ? currentDate : new Date()).toISOString(),
    moduleKey: MODULE_KEY,
    alertId,
    action,
    confidence,
    reason: oneLine(decision?.reason || '판정 근거 없음'),
    ruleStatus,
    ruleId: ruleAdded
      ? `xdr.${MODULE_KEY}.${alertId}`
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
