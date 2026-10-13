const ACTION_THRESHOLDS = Object.freeze({
  block: 0.85,
  alert: 0.5,
});

function getFailureCount(alert, description) {
  const dataCount = Number(alert?.data?.count);

  if (Number.isFinite(dataCount) && dataCount > 0) {
    return dataCount;
  }

  const match = description.match(
    /(?:로그인\s*)?실패\s*(\d+)\s*건|실패\s*(\d+)\s*건/,
  );

  return match
    ? Number(match[1] || match[2])
    : 0;
}

function decideConfidence(alert) {
  const description = String(alert?.rule?.description ?? '');
  const sourceAddress = alert?.data?.srcip;
  const level = Number(alert?.rule?.level ?? 0);

  const mitre = Array.isArray(alert?.rule?.mitre)
    ? alert.rule.mitre
    : [];

  const hasBruteForceTechnique = mitre.includes('T1110');
  const failureCount = getFailureCount(alert, description);

  const hasMultipleAccounts =
    /여러 계정|서로 다른 계정|계정\s*\d+개|계정 이름을 바꿔 가며/
      .test(description);

  const hasPasswordSpraying =
    /같은 비밀번호|동일한 비밀번호|소수의 비밀번호/
      .test(description);

  const hasAttackLanguage =
    /로그인 실패|인증 실패|비밀번호.*실패|실패.*로그인|실패가|실패는|실패가 이어|넣었습니다|시도했습니다|실패\s*\d+\s*건/
      .test(description);

  // 명확한 공격: 다수의 실패 또는 여러 계정 대상 비밀번호 대입
  const clearRepeatedAttack =
    Boolean(sourceAddress) &&
    hasBruteForceTechnique &&
    failureCount >= 20 &&
    level >= 8;

  const clearPasswordSpraying =
    Boolean(sourceAddress) &&
    hasBruteForceTechnique &&
    hasMultipleAccounts &&
    hasPasswordSpraying &&
    hasAttackLanguage;

  if (clearRepeatedAttack || clearPasswordSpraying) {
    return {
      confidence: 0.96,
      reason: clearPasswordSpraying
        ? '여러 계정 대상 비밀번호 대입'
        : '다수의 로그인 실패를 동반한 무차별 대입 공격',
    };
  }

  // 공격 기법과 실패 징후가 있으나 차단 근거가 충분하지 않으면 알림
  if (
    hasBruteForceTechnique &&
    Boolean(sourceAddress) &&
    (failureCount > 0 || hasAttackLanguage)
  ) {
    return {
      confidence: 0.6,
      reason: '무차별 대입 의심 - 추가 확인 필요',
    };
  }

  // 위 조건에 해당하지 않는 이벤트는 기록만 남김
  return {
    confidence: 0.05,
    reason: '명확한 무차별 대입 패턴 없음',
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
