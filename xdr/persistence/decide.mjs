const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

function makeDecision(confidence, reason) {
  const action =
    confidence >= BLOCK_THRESHOLD
      ? 'block'
      : confidence >= ALERT_THRESHOLD
        ? 'alert'
        : 'record';

  return { action, confidence, reason };
}

export function decide(alert) {
  const rule = alert?.rule ?? {};
  const description = rule.description ?? alert?.description ?? '';
  const level = Number(rule.level ?? 0);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre : [];

  if (typeof description !== 'string' || !description.trim()) {
    return makeDecision(0.1, 'no_persistence_pattern');
  }

  const hasService = mitre.includes('T1543');
  const hasTask = mitre.includes('T1053');

  // 명확한 서비스 지속성 공격
  if (
    level >= 10 &&
    hasService &&
    (
      (
        /새 서비스|서비스 등록|서비스 실행 파일이 바뀌|서비스가 변경/u.test(description) &&
        /서명(?:이|은)?\s*없|서명되지 않/u.test(description)
      ) ||
      /평소 목록에 없는 서비스.*다시 켜도 남도록 등록/u.test(description)
    )
  ) {
    return makeDecision(0.9, 'unsigned_new_service');
  }

  // 명확한 예약 작업 지속성 공격
  if (
    level >= 10 &&
    hasTask &&
    (
      (
        /낯선|처음 보는|임의 문자열/u.test(description) &&
        /예약 작업/u.test(description) &&
        /임시 폴더/u.test(description)
      ) ||
      (
        hasService &&
        /시작 프로그램과 예약 작업/u.test(description) &&
        /같은 임시 파일/u.test(description)
      )
    )
  ) {
    return makeDecision(0.9, 'unusual_scheduled_task');
  }

  // 명확한 시작 폴더 지속성 공격
  if (
    level >= 10 &&
    hasService &&
    /시작 폴더|시작 프로그램|시작 항목/u.test(description) &&
    /추가됐|알 수 없|평소 목록에 없/u.test(description)
  ) {
    return makeDecision(0.9, 'startup_folder_change');
  }

  // 불완전한 서비스 신호: 변경·재시작·임시 실행 파일 등
  if (
    level >= 5 &&
    hasService &&
    (
      /서비스 설명만.*바뀌/u.test(description) ||
      /서비스가 한 번 멈췄다가.*다시 시작/u.test(description) ||
      /임시 폴더에 실행 파일.*서비스 등록은 없/u.test(description) ||
      /서비스/u.test(description) &&
        /서명은 확인되지 않았|서명은 아직 모릅니다/u.test(description)
    )
  ) {
    return makeDecision(0.65, 'partial_service_signal');
  }

  // 불완전한 예약 작업 신호: 서명 미확인, 수업 시간, 유사한 이름 등
  if (
    level >= 5 &&
    hasTask &&
    (
      /예약 작업/u.test(description) &&
      (
        /서명은 확인되지 않았/u.test(description) ||
        /실행 시각은 수업 시간/u.test(description) ||
        /이름이 수업 과제와 비슷/u.test(description)
      )
    )
  ) {
    return makeDecision(0.65, 'partial_scheduled_task_signal');
  }

  // 불완전한 시작 폴더 신호: 새 항목이 있으나 후속 실행 근거가 없음
  if (
    level >= 5 &&
    hasService &&
    /시작 항목|시작 폴더/u.test(description) &&
    (
      /서명은 아직 모릅니다/u.test(description) ||
      /변경이 1건/u.test(description)
    )
  ) {
    return makeDecision(0.65, 'partial_startup_signal');
  }

  // 정상 활동 또는 알려진 지속성 신호가 없는 경보
  return makeDecision(0.1, 'no_persistence_pattern');
}
