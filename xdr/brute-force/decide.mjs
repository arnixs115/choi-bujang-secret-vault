
const PATTERNS = Object.freeze([
  {
    id: 'repeated-failures-same-source',
    name: '동일 출발 주소의 연속 로그인 실패',
    evidence: '짧은 시간에 같은 출발 주소에서 로그인 실패가 반복됨',
  },
  {
    id: 'password-spraying-across-accounts',
    name: '여러 계정 대상 비밀번호 대입',
    evidence: '여러 계정에 같은 비밀번호 또는 소수의 비밀번호를 시도함',
  },
]);

const ACTION_THRESHOLDS = Object.freeze({
  block: 0.85,
  alert: 0.5,
});

function getFailureCount(alert, description) {
  const dataCount = Number(alert?.data?.count);

  if (Number.isFinite(dataCount) && dataCount > 0) {
    return dataCount;
  }

  const match = description.match(/로그인 실패\s*(\d+)\s*건|실패\s*(\d+)\s*건/);
  return match ? Number(match[1] ?? match[2]) : 0;
}

function decideConfidence(alert) {
  const description = String(alert?.rule?.description ?? '');
  const lowerDescription = description.toLowerCase();
  const sourceAddress = alert?.data?.srcip;
  const level = Number(alert?.rule?.level ?? 0);
  const mitre = Array.isArray(alert?.rule?.mitre)
    ? alert.rule.mitre
    : [];

  const failureCount = getFailureCount(alert, description);
  const hasBruteForceTechnique = mitre.includes('T1110');

  const hasLoginFailure =
    /로그인 실패|인증 실패|비밀번호.*실패|실패.*로그인/.test(description);

  const hasShortTimeWindow =
    /\d+\s*(초|분)\s*(안|동안|이내)/.test(description);

  const hasMultipleAccounts =
    /여러 계정|서로 다른 계정|계정\s*\d+개|계정 이름을 바꿔 가며/.test(
      description,
    );

  const hasPasswordSpraying =
    /같은 비밀번호|동일한 비밀번호|소수의 비밀번호/.test(description);

  const hasRepeatedFailures =
    hasLoginFailure && failureCount >= 20;

  const sameSourcePattern =
    Boolean(sourceAddress) &&
    hasBruteForceTechnique &&
    hasRepeatedFailures &&
    hasShortTimeWindow;

  const passwordSprayingPattern =
    Boolean(sourceAddress) &&
    hasBruteForceTechnique &&
    hasMultipleAccounts &&
    hasPasswordSpraying &&
    hasLoginFailure;

  if (passwordSprayingPattern) {
    return {
      confidence: 0.98,
      reason: PATTERNS[1].name,
    };
  }

  if (sameSourcePattern) {
    return {
      confidence: 0.96,
      reason: PATTERNS[0].name,
    };
  }

  if (
    hasBruteForceTechnique &&
    hasLoginFailure &&
    failureCount >= 20 &&
    level >= 8
  ) {
    return {
      confidence: 0.78,
      reason: `${PATTERNS[0].name} - 시간 구간 확인 필요`,
    };
  }

  if (
    hasBruteForceTechnique &&
    hasLoginFailure &&
    (failureCount > 0 || level >= 5)
  ) {
    return {
      confidence: 0.6,
      reason: `${PATTERNS[0].name} - 공격 여부 추가 확인 필요`,
    };
  }

  // MITRE T1110이 없고 명확한 실패 패턴도 없다면
  // 정상 이벤트를 불필요하게 공격으로 분류하지 않는다.
  if (!hasLoginFailure || !hasBruteForceTechnique) {
    return {
      confidence: 0.05,
      reason: '일치하는 무차별 대입 패턴 없음',
    };
  }

  return {
    confidence: 0.3,
    reason: '근거 부족 - 일치하는 패턴이 명확하지 않음',
  };
}

export function decide(alert) {
  const { confidence, reason } = decideConfidence(alert);

  let action = 'record';

  if (confidence >= ACTION_THRESHOLDS.block) {
    action = 'block';
  } else if (confidence >= ACTION_THRESHOLDS.alert) {
    action = 'alert';
  }

  return {
    action,
    confidence,
    reason: String(reason).split('\n')[0],
  };
}
