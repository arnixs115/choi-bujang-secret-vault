
const PATTERNS = Object.freeze([
  {
    id: 'sql-syntax-in-request-argument',
    name: '요청 인자 안의 SQL 구문',
    condition:
      '요청 입력값의 SQL 구문 표식과 반복 여부를 확인한다.',
    evidence:
      'MITRE ATT&CK T1190은 외부 공개 애플리케이션 악용을 다루며, SQL 삽입 징후는 조사 단서가 될 수 있다.',
    source: 'https://attack.mitre.org/techniques/T1190/',
    marker: /doc-sql-(?:chain|or|select-chain)|doc-mixed-marker/i,
    description:
      /SQL 구문을 이어 붙인 요청|SQL 구문 표기가 한 주소에서|데이터베이스 조회를 이어 붙이는 표기|SQL 표식/i,
  },
  {
    id: 'script-tag-in-request-argument',
    name: '요청 인자 안의 스크립트 태그',
    condition:
      '요청 입력값의 스크립트 삽입 표식과 반복 여부를 확인한다.',
    evidence:
      'MITRE ATT&CK T1190은 외부 공개 애플리케이션 악용을 다루며, 스크립트 삽입 징후는 조사 단서가 될 수 있다.',
    source: 'https://attack.mitre.org/techniques/T1190/',
    marker: /doc-script-marker|doc-mixed-marker/i,
    description:
      /스크립트 삽입 표기가|스크립트 표식과 SQL 표식/i,
  },
  {
    id: 'repeated-path-traversal',
    name: '반복되는 경로 거슬러 올라가기 표기',
    condition:
      '요청 입력값의 경로 이탈 표식과 반복 여부를 확인한다.',
    evidence:
      'MITRE ATT&CK T1190은 외부 공개 애플리케이션 악용을 다루며, 반복되는 경로 이탈 표기는 조사 단서가 될 수 있다.',
    source: 'https://attack.mitre.org/techniques/T1190/',
    marker: /doc-up-repeat/i,
    description:
      /경로를 여러 단계 거슬러 올라가는 표기|경로 이탈 표기가 같은 주소에서/i,
  },
]);

const THRESHOLDS = Object.freeze({
  block: 0.85,
  alert: 0.5,
});

function getText(alert) {
  return [
    alert?.data?.url,
    alert?.rule?.description,
  ]
    .filter((value) => typeof value === 'string')
    .join(' ');
}

function getCount(alert) {
  const count = Number(alert?.data?.count);
  return Number.isFinite(count) && count >= 0 ? count : 0;
}

function getConfidence(alert, pattern) {
  const text = getText(alert);
  const markerMatch = pattern.marker.test(text);
  const descriptionMatch = pattern.description.test(text);

  if (!markerMatch && !descriptionMatch) {
    return 0;
  }

  const count = getCount(alert);
  const repeated = count >= 3 &&
    /반복|번 들어왔습니다|번 나왔습니다/.test(text);

  // 명시적인 패턴과 반복 신호가 함께 있어야 block 수준으로 판정한다.
  if (markerMatch && descriptionMatch && repeated) {
    return 0.95;
  }

  // 패턴 단서가 있지만 반복 증거가 부족하면 추가 확인 대상으로 둔다.
  return 0.65;
}

export function decide(alert) {
  const matches = PATTERNS
    .map((pattern) => ({
      pattern,
      confidence: getConfidence(alert, pattern),
    }))
    .filter((match) => match.confidence > 0);

  let confidence = 0;
  let reason = '등록 패턴과 일치하지 않음';

  if (matches.length > 0) {
    confidence = Math.max(
      ...matches.map((match) => match.confidence),
    );

    reason = matches
      .filter((match) => match.confidence === confidence)
      .map((match) => match.pattern.name)
      .join(', ');
  }

  const description = String(alert?.rule?.description ?? '');

  const ambiguousSignal =
    /이상한 검색 1건|주입처럼 보이는 표기가 1건|구분 문자가 1건/.test(
      description,
    );

  if (confidence === 0 && ambiguousSignal) {
    confidence = 0.6;
    reason =
      '미확정 단발 신호 — SQL 구문·스크립트 태그·경로 거슬러 올라가기 패턴을 특정할 수 없음';
  }

  const action =
    confidence >= THRESHOLDS.block
      ? 'block'
      : confidence >= THRESHOLDS.alert
        ? 'alert'
        : 'record';

  return { action, confidence, reason };
}

