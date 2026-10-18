// XDR 연결 계층. src/decider.mjs는 수정하지 않고, 그 앞에서만 동작한다.
//
// 응답 계약
//  - XDR 규칙에 걸리면: { decision:'deny', source:'xdr-guard', reasonCode:'xdr_web_injection_ip_denied',
//                         ruleId:'xdr-wi-…', evidenceAlertId, expiresAt }
//  - 걸리지 않으면: 기존 decide(request)의 반환값을 가공 없이 그대로 돌려준다.
//  - 규칙 ID는 항상 'xdr-wi-' 접두사. 기존 RULE_IDS(starter.deny 등)와 섞이지 않는다.
//  - 출발지 IP는 반드시 sourceIp 인자(신뢰 경로에서 얻은 값)로만 받는다.
//    request/경보 본문의 IP 필드는 보지 않는다.
//
// [확인 필요] decider의 실제 응답 5개 항목 이름을 읽지 못했으므로, 소비자가 그 형식을 기대한다면
// toDenyResponse 한 곳만 그 이름에 맞게 고치세요.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_RULES_PATH, activeRules, normalizeIp, readRules,
} from '../xdr/web-injection/rule-store.mjs';

export const XDR_DENY_SOURCE = 'xdr-guard';
export const XDR_DENY_REASON_CODE = 'xdr_web_injection_ip_denied';
export const XDR_RULE_ID_PREFIX = 'xdr-wi-';
export const isXdrRuleId = (id) => typeof id === 'string' && id.startsWith(XDR_RULE_ID_PREFIX);

export function toDenyResponse(rule) {
  return {
    decision: 'deny',
    source: XDR_DENY_SOURCE,
    reasonCode: XDR_DENY_REASON_CODE,
    ruleId: rule.id,
    evidenceAlertId: rule.evidenceAlertId,
    expiresAt: rule.expiresAt,
  };
}

async function loadDefaultDecide() {
  const mod = await import(new URL('./decider.mjs', import.meta.url));
  return mod.decide;
}

/**
 * @param {object} request          기존 decide()가 받는 요청 그대로
 * @param {object} ctx
 * @param {string} ctx.sourceIp     신뢰할 수 있는 처리 경로에서 얻은 출발지 IP
 * @param {number} [ctx.now]
 * @param {string} [ctx.rulesPath]
 * @param {Function} [ctx.decide]   기본값: src/decider.mjs의 decide
 * @param {Function} [ctx.onWarning] 규칙 파일을 못 읽었을 때 호출(이 경우 기존 판정기로 넘김)
 */
export async function guardedDecide(request, ctx = {}) {
  const { sourceIp, now = Date.now(), rulesPath = DEFAULT_RULES_PATH, onWarning } = ctx;
  const decide = ctx.decide ?? (await loadDefaultDecide());

  const ip = normalizeIp(sourceIp);
  if (ip) {
    let rules = [];
    try {
      rules = activeRules(await readRules(rulesPath), now);
    } catch (err) {
      onWarning?.(err); // 규칙 저장소 오류로 정상 요청 전체를 막지 않는다.
    }
    const hit = rules.find((r) => r.effect === 'deny' && r.sourceIp === ip);
    if (hit) return toDenyResponse(hit);
  }
  return decide(request);
}
