const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

function decision(confidence, reason) {
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
    return decision(0.1, 'no_persistence_pattern');
  }

  // 1. 서명되지 않은 서비스 등록·변경 또는 재부팅 후에도 남는 서비스
  if (
    level >= 10 &&
    mitre.includes('T1543') &&
    /서비스/u.test(description) &&
    (
      (
        /새 서비스|서비스 등록|서비스 실행 파일이 바뀌|서비스가 변경/u.test(description) &&
        /서명(?:이|은)?\s*없|서명되지 않/u.test(description)
      ) ||
      /평소 목록에 없는 서비스.*다시 켜도 남도록 등록/u.test(description)
    )
  ) {
    return decision(0.9, 'unsigned_new_service');
  }

  // 2. 낯선 예약 작업 또는 시작 프로그램과 예약 작업의 복합 지속성 신호
  if (
    level >= 10 &&
    mitre.includes('T1053') &&
    /예약 작업/u.test(description) &&
    (
      (
        /낯선|처음 보는|임의 문자열/u.test(description) &&
        /임시 폴더/u.test(description)
      ) ||
      (
        mitre.includes('T1543') &&
        /시작 프로그램과 예약 작업/u.test(description) &&
        /같은 임시 파일/u.test(description)
      )
    )
  ) {
    return decision(0.9, 'unusual_scheduled_task');
  }

  // 3. 시작 폴더에 평소 목록에 없는 프로그램이 추가된 경우
  if (
    level >= 10 &&
    mitre.includes('T1543') &&
    /시작 폴더|시작 프로그램|시작 항목/u.test(description) &&
    /추가됐|알 수 없|평소 목록에 없/u.test(description)
  ) {
    return decision(0.9, 'startup_folder_change');
  }

  // 공격 근거가 충분하지 않은 모호한 이벤트와 정상 이벤트는 기록만 한다.
  return decision(0.1, 'no_persistence_pattern');
}
