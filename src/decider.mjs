// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 등록 기기의 자료실 읽기만 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required',]);

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

export async function decide(request) {
  // 입력이 계약에 맞지 않으면 정상 요청으로 취급하지 않는다.
  if (!validSignals(request.signals) || !validRecentEvents(request.recentEvents)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: ['starter.deny'],
    };
  }

  // 등록되지 않았거나 등록 상태가 없는 기기는 거부
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

    // 평소와 다른 시각 + 낯선 네트워크 + 갑작스러운 대량 접근이면 추가 확인
  const unusualHour = request.signals.hour < 6
    || request.signals.hour >= 22;

  const unusualNetwork = request.signals.network === 'unusual';

  const burstRead = request.recentEvents.some(event =>
    event.kind === 'risk_signal'
    && event.count >= 10
    && event.ageSeconds <= 300
  );

  if (unusualHour && unusualNetwork && burstRead) {
    // 추가 확인을 완료한 경우에만 정상 자료실 읽기를 허용한다.
    if (request.stepUp?.verified === true
        && Number.isInteger(request.stepUp.authAgeSeconds)
        && request.stepUp.authAgeSeconds >= 0
        && request.stepUp.authAgeSeconds <= 300) {
      const isNotesRead = request.method === 'GET'
        && (
          request.route === 'GET /notes'
          || request.route === 'GET /notes/:id'
        );

      if (isNotesRead) {
        return {
          schema: 'aleph.decision.v1',
          requestId: request.requestId,
          decision: 'allow',
          reasonCode: 'approved',
          ruleIds: ['step_up_required'],
        };
      }
    }

    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  // 등록된 기기의 자료실 읽기 요청만 허용
  const isNotesRead = request.method === 'GET'
    && (
      request.route === 'GET /notes'
      || request.route === 'GET /notes/:id'
    );

  if (isNotesRead) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'allow',
      reasonCode: 'approved',
      ruleIds: ['device_registered'],
    };
  }

  // 다른 요청은 기존 기본 거부 규칙 유지
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: ['starter.deny'],
  };
}
