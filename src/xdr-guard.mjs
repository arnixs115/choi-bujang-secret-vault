// XDR 연결 계층. src/decider.mjs는 수정하지 않고, 그 앞에서만 동작한다.
//
// 응답 계약 (docs/DECIDER_REQUEST.md의 aleph.decision.v1 응답 5개 항목을 그대로 따른다)
//  - guardedDecide(request, ctx) → 항상 5개 이름만 가진 판정 응답.
//      · XDR 규칙에 걸리면:
//          { schema:'aleph.decision.v1', requestId, decision:'deny',
//            reasonCode:'xdr_web_injection_ip_denied', ruleIds:['xdr-wi-…'] }
//      · 걸리지 않으면: 기존 decide(request)의 반환값을 가공 없이 그대로(같은 객체) 돌려준다.
//  - guardedDecideDetailed(request, ctx) → { response, xdr }
//      · response: 위와 같은 판정 응답
//      · xdr: 거부된 경우 { source:'xdr-guard', ruleId, evidenceAlertId, expiresAt }, 아니면 null
//      · 거부 근거 규칙 ID는 response.ruleIds[0]과 xdr.ruleId에, 근거 경보 ID는 xdr.evidenceAlertId에 있다.
//        판정 응답에는 5개 항목 밖의 이름을 넣지 않는다(엔진이 형식이 다른 응답을 거부하므로).
//  - XDR 규칙 ID는 항상 'xdr-wi-' 접두사. 기존 RULE_IDS(starter.deny, device_registered,
//    step_up_required, resource_zone_policy)와 섞이지 않는다.
//  - 출발지 IP는 반드시 ctx.sourceIp(신뢰 경로에서 얻은 값)로만 받는다.
//    request/경보 본문의 IP 필드는 보지 않는다. (decide 요청 계약 18개 항목에는 IP가 없다.)
//
// [운영 등록부 확인 필요] reasonCode 'xdr_web_injection_ip_denied'와 ruleIds의 'xdr-wi-…'가
// 실제 엔진의 allowedReasonCodes / 규칙 이름 등록부에 허용돼 있는지는 이 저장소에서 확인할 수 없다.
import {
  DEFAULT_RULES_PATH, activeRules, normalizeIp, readRules,
} from '../xdr/web-injection/rule-store.mjs';

export const DECISION_SCHEMA = 'aleph.decision.v1';
export const XDR_DENY_SOURCE = 'xdr-guard';
export const XDR_DENY_REASON_CODE = 'xdr_web_injection_ip_denied';
export const XDR_RULE_ID_PREFIX = 'xdr-wi-';
export const isXdrRuleId = (id) => typeof id === 'string' && id.startsWith(XDR_RULE_ID_PREFIX);

/** 엔진 계약과 같은 5개 이름만 가진 거부 응답. */
export function toDenyResponse(request, rule) {
  return {
    schema: DECISION_SCHEMA,
    requestId: request?.requestId,
    decision: 'deny',
    reasonCode: XDR_DENY_REASON_CODE,
    ruleIds: [rule.id],
  };
}

/** 거부 근거(응답 밖 정보). */
export function toEvidence(rule) {
  return {
    source: XDR_DENY_SOURCE,
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
 * @returns {Promise<{response: object, xdr: object|null}>}
 */
export async function guardedDecideDetailed(request, ctx = {}) {
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
    if (hit) return { response: toDenyResponse(request, hit), xdr: toEvidence(hit) };
  }
  return { response: await decide(request), xdr: null };
}

/** 판정 응답만 필요할 때. 엔진/판정기와 같은 5개 항목 형식을 돌려준다. */
export async function guardedDecide(request, ctx = {}) {
  return (await guardedDecideDetailed(request, ctx)).response;
}
