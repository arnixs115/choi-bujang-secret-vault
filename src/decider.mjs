// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 등록 기기의 자료실 읽기만 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required', 'resource_zone_policy',]);

function validSignals(signals) {
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    return false;
  }

  const keys = Object.keys(signals).sort().join(',');
  if (keys !== 'hour,network,region,source') return false;

  // 엔진 계약에 정의된 출처만 허용한다.
  const validSources = ['none', 'judge_fixture'];
  if (!validSources.includes(signals.source)) {
    return false;
  }

  // 정보가 없거나 공백뿐인 값은 정상 정보로 보정하지 않는다.
  if (typeof signals.region !== 'string'
      || signals.region.trim().length === 0) {
    return false;
  }

  if (typeof signals.network !== 'string'
      || signals.network.trim().length === 0) {
    return false;
  }

  if (!Number.isInteger(signals.hour)
      || signals.hour < 0
      || signals.hour > 23) {
    return false;
  }
  if (signals.source === 'none'
      && (signals.region !== 'unknown' || signals.network !== 'unknown')) {
    return false;
  }

  // 출처의 의미를 구분한다.
  // none: 실제 경로에서 신뢰 가능한 지역·네트워크 신호가 없음
  // judge_fixture: 심판이 제공한 가상 테스트 신호
  // 둘 다 입력 형식 검사 통과일 뿐, 실제 접속 증거라는 뜻은 아니다.
  return true;
}

function validRecentEvents(events) {
  if (!Array.isArray(events) || events.length > 12) return false;

  return events.every(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      return false;
    }

    if (Object.keys(event).sort().join(',') !== 'ageSeconds,count,kind') {
      return false;
    }

    return typeof event.kind === 'string'
      && event.kind.trim().length > 0
      && Number.isInteger(event.ageSeconds)
      && event.ageSeconds >= 0
      && Number.isInteger(event.count)
      && event.count >= 1;
  });
}

function resourceZoneAllows(request) {
  // 쿼리로 기능을 선택하는 요청은 거부
  if (
    request.queryLength !== 0 ||
    typeof request.service !== 'string' ||
    typeof request.method !== 'string' ||
    typeof request.path !== 'string' ||
    typeof request.route !== 'string'
  ) {
    return false;
  }

  const { service, method, path, route } = request;

  // 메모: 목록은 거부하고 단일 ID 경로만 허용
  // ID 형식은 제한하지 않으며, 소유권 검사는 API에서 수행
  if (service === 'notes') {
    return (
      /^\/notes\/[^/?#]+$/u.test(path) &&
      method === 'GET' &&
      route === 'GET /notes/:id'
    );
  }

  // 반 공지: 읽기 전용
  if (service === 'announcements') {
    if (method !== 'GET') return false;

    if (path === '/announcements') {
      return route === 'GET /announcements';
    }

    return (
      /^\/announcements\/[^/?#]+$/u.test(path) &&
      route === 'GET /announcements/:id'
    );
  }

  // 강사 자료 및 알 수 없는 서비스는 거부
  return false;
}


function decisionResponse(request, decision, reasonCode, ruleIds) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds,
  };
}

export async function decide(request) {
  if (
    !request ||
    !validSignals(request.signals) ||
    !validRecentEvents(request.recentEvents)
  ) {
    return decisionResponse(
      request ?? {},
      'deny',
      'starter_not_ready',
      ['starter.deny'],
    );
  }

  // 기존 6단계: 등록되지 않은 기기는 거부
  if (request.deviceRegistered !== true) {
    return decisionResponse(
      request,
      'deny',
      'device_not_registered',
      ['device_registered'],
    );
  }

  // 구역 정책을 통과하지 못하면 추가 확인으로 우회할 수 없음
  if (!resourceZoneAllows(request)) {
    return decisionResponse(
      request,
      'deny',
      'starter_not_ready',
      ['resource_zone_policy'],
    );
  }

  // 기존 7단계: 복합 이상 접속 탐지
  const unusualHour =
    request.signals.hour < 6 || request.signals.hour >= 22;

  const unusualNetwork = request.signals.network === 'unusual';

  const burstRead = request.recentEvents.some(event =>
    event.kind === 'risk_signal' &&
    event.count >= 10 &&
    event.ageSeconds <= 300
  );

  if (unusualHour && unusualNetwork && burstRead) {
    const recentlyVerified =
      request.stepUp?.verified === true &&
      Number.isInteger(request.stepUp.authAgeSeconds) &&
      request.stepUp.authAgeSeconds >= 0 &&
      request.stepUp.authAgeSeconds <= 300;

    if (recentlyVerified && request.method === 'GET') {
      return decisionResponse(
        request,
        'allow',
        'approved',
        ['step_up_required'],
      );
    }

    return decisionResponse(
      request,
      'step_up',
      'step_up_required',
      ['step_up_required'],
    );
  }

  return decisionResponse(
    request,
    'allow',
    'approved',
    ['resource_zone_policy'],
  );
}
