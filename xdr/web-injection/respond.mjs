// XDR 웹 주입 대응 모듈.
// decide.mjs의 결과(action/confidence)와 경보 원본을 받아, 명확한 공격만 15분짜리 임시 거부 규칙으로 등록한다.
// decide.mjs는 호출만 하지 않고(이 파일은 import하지 않음) 결과만 입력으로 받는다.
import { promises as fs } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_RULES_PATH, RuleStoreError, addRule, isBlockableIp, normalizeIp,
} from './rule-store.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

export const CONFIDENCE_THRESHOLD = 0.85;
export const RULE_TTL_MS = 15 * 60 * 1000;
export const RULE_EFFECT = 'deny';
export const RULE_ID_PREFIX = 'xdr-wi-'; // 기존 src/decider.mjs의 RULE_IDS와 겹치지 않는 접두사
export const DEFAULT_ALERTS_LOG = path.resolve(here, '..', 'alerts.log');

// 경보 모양 (xdr/fixtures/web-injection.json 확인 결과):
//   { id, rule:{ description, level, mitre }, data:{ srcip, url, count(문자열) } }
export const ALERT_ID_PATHS = ['id'];
export const SOURCE_IP_PATHS = ['data.srcip']; // 경보 안의 다른 문자열에서 IP를 긁어 오지 않는다.
export const MIN_REPEAT_COUNT = 3;

// 웹 주입 근거 계열. 근거는 data.url에서만 찾는다(설명문만으로는 등록하지 않음).
//  (a) payload: URL에 실제 주입 페이로드가 있음
//  (b) marker : fixture의 표식(doc-*)이 URL에 있고, 같은 계열의 설명문이 있고, data.count >= 3
// marker/description 값은 decide.mjs의 판정 표식을 복제한 것이므로 decide.mjs가 바뀌면 함께 고쳐야 한다.
export const EVIDENCE_FAMILIES = [
  {
    family: 'sql_injection',
    payload: /\bunion\s+(?:all\s+)?select\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|;\s*drop\s+table\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\binformation_schema\b|\bxp_cmdshell\b/i,
    marker: /doc-sql-(?:chain|or|select-chain)|doc-mixed-marker/i,
    description: /SQL 구문을 이어 붙인 요청|SQL 구문 표기가 한 주소에서|데이터베이스 조회를 이어 붙이는 표기|SQL 표식/i,
  },
  {
    family: 'script_injection',
    payload: /<\s*script\b|\bjavascript\s*:|\bon(?:error|load|click|mouseover|focus)\s*=|<\s*svg\b[^>]*\bonload\s*=/i,
    marker: /doc-script-marker|doc-mixed-marker/i,
    description: /스크립트 삽입 표기가|스크립트 표식과 SQL 표식/i,
  },
  {
    family: 'path_traversal',
    payload: /(?:\.\.[\/\\]){2,}|\/etc\/passwd\b|\bwin\.ini\b|\bboot\.ini\b/i,
    marker: /doc-up-repeat/i,
    description: /경로를 여러 단계 거슬러 올라가는 표기|경로 이탈 표기가 같은 주소에서/i,
  },
  {
    family: 'command_injection',
    payload: /(?:;|\|\||\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)(?=[\s;|&)`]|$)/i,
    marker: /doc-cmd-separator/i,
    description: /명령 구분자 표기가/i,
  },
  { family: 'template_or_jndi_injection', payload: /\$\{\s*jndi:|\{\{\s*\d+\s*\*\s*\d+\s*\}\}/i },
  { family: 'xxe', payload: /<!ENTITY\b|<!DOCTYPE[^>]+\[/i },
];

function getPath(obj, dotted) {
  return dotted.split('.').reduce((cur, key) => (cur && typeof cur === 'object' ? cur[key] : undefined), obj);
}

function firstString(obj, paths) {
  for (const p of paths) {
    const v = getPath(obj, p);
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}

export const extractAlertId = (alert) => firstString(alert, ALERT_ID_PATHS);
export const extractSourceIp = (alert) => firstString(alert, SOURCE_IP_PATHS);

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** data.url(URL 인코딩 2단계 해제 포함)에서 웹 주입 근거 계열을 찾는다. 설명문만 있으면 근거로 보지 않는다. */
export function findInjectionEvidence(alert) {
  const url = alert?.data?.url;
  if (typeof url !== 'string' || !url) return [];
  const once = safeDecode(url);
  const haystack = [url, once, safeDecode(once)].join('\n');
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const count = Number(alert?.data?.count);
  const repeated = Number.isFinite(count) && count >= MIN_REPEAT_COUNT;

  return EVIDENCE_FAMILIES.filter((f) => {
    if (f.payload?.test(haystack)) return true;
    return Boolean(f.marker && f.marker.test(haystack) && f.description?.test(description) && repeated);
  }).map((f) => f.family);
}

function skip(skipReason, extra = {}) {
  return { status: 'skipped', skipReason, ...extra };
}

function summarizeReason(decision) {
  const r = decision?.reason ?? decision?.reasons ?? '';
  const s = Array.isArray(r) ? r.join('; ') : String(r);
  return s.length > 200 ? `${s.slice(0, 200)}…` : s;
}

/** 등록 가능 여부만 판단한다(파일 접근 없음). */
export function evaluate(alert, decision) {
  if (!alert || typeof alert !== 'object' || !decision || typeof decision !== 'object') {
    return skip('invalid_input');
  }
  if (decision.action !== 'block') return skip('not_block');
  if (typeof decision.confidence !== 'number' || !Number.isFinite(decision.confidence)
    || decision.confidence < CONFIDENCE_THRESHOLD) return skip('low_confidence');

  const alertId = extractAlertId(alert);
  if (!alertId) return skip('missing_alert_id');
  if (typeof decision.alertId === 'string' && decision.alertId !== alertId) {
    return skip('alert_id_mismatch');
  }

  const rawIp = extractSourceIp(alert);
  if (!rawIp) return skip('missing_source_ip');
  const sourceIp = normalizeIp(rawIp);
  if (!sourceIp) return skip('invalid_source_ip');
  if (!isBlockableIp(sourceIp)) return skip('non_blockable_ip');

  const families = findInjectionEvidence(alert);
  if (families.length === 0) return skip('no_attack_evidence');

  return { status: 'eligible', alertId, sourceIp, families };
}

async function appendLog(line, logPath) {
  try {
    await fs.mkdir(path.dirname(logPath), { recursive: true });
    await fs.appendFile(logPath, JSON.stringify(line) + '\n', 'utf8');
    return { ok: true };
  } catch (err) {
    return { ok: false, errorKind: 'io_error', error: String(err?.code ?? err?.message) };
  }
}

/**
 * @param {object} alert    경보 원본
 * @param {object} decision decide.mjs의 결과 { action, confidence, reason, ... }
 * @param {object} [opts]   { now, rulesPath, alertsLogPath, ttlMs }
 * @returns 규칙 등록 결과(rule)와 알림 기록 결과(log)를 분리해서 돌려준다.
 */
export async function respond(alert, decision, opts = {}) {
  const {
    now = Date.now(), rulesPath = DEFAULT_RULES_PATH,
    alertsLogPath = DEFAULT_ALERTS_LOG, ttlMs = RULE_TTL_MS,
  } = opts;

  const verdict = evaluate(alert, decision);
  let rule = verdict;
  let expiresAt = null;
  let reason = summarizeReason(decision);

  if (verdict.status === 'eligible') {
    const candidate = {
      id: `${RULE_ID_PREFIX}${randomUUID()}`,
      effect: RULE_EFFECT,
      sourceIp: verdict.sourceIp,
      expiresAt: new Date(now + ttlMs).toISOString(),
      evidenceAlertId: verdict.alertId,
      reason: `웹 주입 근거(${verdict.families.join(',')}), 확신도 ${decision.confidence}`,
      createdAt: new Date(now).toISOString(),
    };
    try {
      const res = await addRule(candidate, { rulesPath, now });
      if (res.added) {
        rule = { status: 'registered', ruleId: candidate.id, rule: candidate };
        expiresAt = candidate.expiresAt;
        reason = candidate.reason;
      } else {
        rule = { status: 'duplicate', ruleId: res.duplicate.id };
        expiresAt = res.duplicate.expiresAt;
      }
    } catch (err) {
      const kind = err instanceof RuleStoreError ? err.kind : 'registration_failed';
      rule = { status: 'failed', errorKind: kind, error: err?.message ?? String(err) };
    }
  }

  const log = await appendLog({
    ts: new Date(now).toISOString(),
    moduleKey: 'web-injection', // alerts.log는 brute-force 줄과 함께 쓰므로 모듈을 구분한다.
    alertId: extractAlertId(alert ?? {}) ?? null,
    action: decision?.action ?? null,
    confidence: decision?.confidence ?? null,
    reason,
    ruleResult: {
      status: rule.status,
      ...(rule.ruleId ? { ruleId: rule.ruleId } : {}),
      ...(rule.skipReason ? { skipReason: rule.skipReason } : {}),
      ...(rule.errorKind ? { errorKind: rule.errorKind } : {}),
    },
    expiresAt,
  }, alertsLogPath);

  return {
    alertId: extractAlertId(alert ?? {}) ?? null,
    action: decision?.action ?? null,
    confidence: decision?.confidence ?? null,
    rule,
    log,
  };
}
