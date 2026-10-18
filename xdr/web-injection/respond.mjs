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

// ──────────────────────────────────────────────────────────────
// [확인 필요] 아래 후보 경로는 xdr/fixtures/web-injection.json을 읽지 못한 채 가정한 것입니다.
// 실제 필드명이 다르면 이 두 배열만 고치면 됩니다.
export const ALERT_ID_PATHS = ['id', 'alertId', 'alert_id'];
export const SOURCE_IP_PATHS = [
  'sourceIp', 'srcIp', 'src_ip', 'source_ip', 'sourceIP', 'clientIp', 'client_ip',
  'source.ip', 'src.ip', 'network.srcIp', 'network.source_ip',
];
// ──────────────────────────────────────────────────────────────

// 웹 주입 근거 패턴. decide.mjs와 별개로 대응 계층이 직접 확인한다.
// 근거 문장(설명문)만 있고 실제 페이로드가 없는 경보는 일부러 등록하지 않는다.
export const EVIDENCE_PATTERNS = [
  { family: 'sql_injection', re: /\bunion\s+(?:all\s+)?select\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|;\s*drop\s+table\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\binformation_schema\b|\bxp_cmdshell\b/i },
  { family: 'xss', re: /<\s*script\b|\bjavascript\s*:|\bon(?:error|load|click|mouseover|focus)\s*=|<\s*svg\b[^>]*\bonload\s*=/i },
  { family: 'path_traversal', re: /(?:\.\.[\/\\]){2,}|\/etc\/passwd\b|\bwin\.ini\b|\bboot\.ini\b/i },
  { family: 'command_injection', re: /(?:;|\|\||\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)(?=[\s;|&)`]|$)/i },
  { family: 'template_or_jndi_injection', re: /\$\{\s*jndi:|\{\{\s*\d+\s*\*\s*\d+\s*\}\}/i },
  { family: 'xxe', re: /<!ENTITY\b|<!DOCTYPE[^>]+\[/i },
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

function collectStrings(value, out, depth = 0) {
  if (out.size > 20000 || depth > 6) return;
  if (typeof value === 'string') out.text += value + '\n';
  else if (Array.isArray(value)) value.forEach((v) => collectStrings(v, out, depth + 1));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => collectStrings(v, out, depth + 1));
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** 경보 안의 모든 문자열(URL 인코딩 2단계 해제 포함)에서 웹 주입 패턴 계열을 찾는다. */
export function findInjectionEvidence(alert) {
  const acc = { text: '', get size() { return this.text.length; } };
  collectStrings(alert, acc);
  const once = safeDecode(acc.text);
  const haystack = [acc.text, once, safeDecode(once)].join('\n');
  return EVIDENCE_PATTERNS.filter(({ re }) => re.test(haystack)).map(({ family }) => family);
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
