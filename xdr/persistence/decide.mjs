const PATTERNS = [
  {
    name: 'unsigned_new_service',
    condition:
      '새 서비스 등록 또는 서비스 실행 파일 변경과 서명되지 않은 실행 파일이 함께 명시됨',
    evidence:
      'MITRE ATT&CK T1543 — 시스템 프로세스 생성·변경은 서비스 기반 지속성 동작과 관련된다.',
    matches: (description) =>
      /서비스/u.test(description) &&
      /새 서비스|서비스 등록|서비스 실행 파일이 바뀌|서비스가 변경/u.test(
        description,
      ) &&
      /서명(?:이|은)?\s*없|서명되지 않/u.test(description),
    confidence: 0.9,
  },
  {
    name: 'unusual_scheduled_task',
    condition:
      '낯설거나 처음 보는 예약 작업이 임시 폴더의 프로그램을 실행한다고 명시됨',
    evidence:
      'MITRE ATT&CK T1053 — 예약 작업은 예약 실행을 통한 지속성 확보에 악용될 수 있다.',
    matches: (description) =>
      /예약 작업/u.test(description) &&
      /낯선|처음 보는|임의 문자열/u.test(description) &&
      /임시 폴더/u.test(description),
    confidence: 0.9,
  },
  {
    name: 'startup_folder_change',
    condition:
      '시작 폴더 또는 시작 프로그램 항목에 알 수 없는 새 프로그램이 추가됐다고 명시됨',
    evidence:
      'MITRE ATT&CK T1543 — 시작 구성 변경은 지속성 동작을 식별하는 단서가 될 수 있다.',
    matches: (description) =>
      /시작 폴더|시작 프로그램|시작 항목/u.test(description) &&
      /추가됐|알 수 없|평소 목록에 없/u.test(description),
    confidence: 0.65,
  },
];

const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

function descriptionOf(alert) {
  const value = alert?.rule?.description ?? alert?.description ?? '';
  return typeof value === 'string' ? value : '';
}

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
  const description =
    alert?.rule?.description ?? alert?.description ?? '';

  if (typeof description !== 'string' || !description.trim()) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: 'no_persistence_pattern',
    };
  }

  const matched = PATTERNS.filter((pattern) =>
    pattern.matches(description),
  );

  if (matched.length === 0) {
    return {
      action: 'record',
      confidence: 0.1,
      reason: 'no_persistence_pattern',
    };
  }

  // 여러 패턴이 일치하면 가장 높은 신뢰도를 사용한다.
  const best = matched.reduce((current, next) =>
    next.confidence > current.confidence ? next : current,
  );

  const action =
    best.confidence >= 0.85
      ? 'block'
      : best.confidence >= 0.5
        ? 'alert'
        : 'record';

  return {
    action,
    confidence: best.confidence,
    reason: best.name,
  };
}
