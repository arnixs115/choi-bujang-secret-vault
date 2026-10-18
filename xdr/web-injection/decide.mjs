// 웹 주입 판단 모듈. 경보 하나를 받아 { action, confidence, reason } 만 돌려준다.
// 파일 입출력·판정기 연결은 하지 않는다(그건 respond.mjs 몫).
//
// 판단 순서
//  1) 요청 주소(data.url)를 두 번까지 URL 해제한 뒤, SQL·스크립트·경로 거슬러 올라가기·명령 구분자 형태를 찾는다.
//     (수업용 경보의 doc-* 표식도 같은 주소 신호로 본다.)
//  2) 반복 여부는 data.count(같은 출발 주소의 누적 횟수)로 본다. 3번 이상이면 반복.
//  3) 주소 신호 + 반복 → block (확신도 0.9 이상).
//  4) 막을 근거는 부족하지만 경보 자체가 웹 공격으로 표시된 경우(rule.mitre 에 T1190, 또는 rule.level 5 이상)
//     → alert (확신도 0.5 이상 0.85 미만). 주소 신호가 있으면 더 높게, 없으면 낮게 둔다.
//  5) 공격 표시도 신호도 없는 일반 조회는 → record.
//     설명문 문구만으로 애매함을 정하지 않는다. 설명문은 패턴 일치 확인과 확신도 보정에만 쓴다.
// 경보에는 한 번에 한 출발 주소의 집계만 들어 있으므로, 같은 주소 여부는 count 가 대신한다.

const THRESHOLDS = Object.freeze({ block: 0.85, alert: 0.5 });
const REPEAT_MIN = 3;

const FAMILIES = Object.freeze([
  {
    id: 'sql',
    name: '요청 인자 안의 SQL 구문',
    payload: /\bunion\s+(?:all\s+)?select\b|'\s*or\s*'?\d+'?\s*=\s*'?\d+|\bor\s+1\s*=\s*1\b|;\s*drop\s+table\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\binformation_schema\b|\bselect\b[^&#]{1,60}\bfrom\b/i,
    marker: /doc-sql-(?:chain|or|select-chain)|doc-mixed-marker/i,
    description: /SQL 구문을 이어 붙인|SQL 구문 표기가|데이터베이스 조회를 이어 붙이는|SQL 표식/i,
  },
  {
    id: 'script',
    name: '요청 인자 안의 스크립트 태그',
    payload: /<\s*script\b|\bjavascript\s*:|\bon(?:error|load|click|mouseover|focus)\s*=/i,
    marker: /doc-script-marker|doc-mixed-marker/i,
    description: /스크립트 삽입 표기가|스크립트 표식과/i,
  },
  {
    id: 'path',
    name: '반복되는 경로 거슬러 올라가기 표기',
    payload: /(?:\.\.[\/\\]){2,}|\/etc\/passwd\b|\bwin\.ini\b/i,
    marker: /doc-up-repeat/i,
    description: /경로를 여러 단계 거슬러 올라가는|경로 이탈 표기가/i,
  },
  {
    id: 'command',
    name: '요청 인자 안의 명령 구분자',
    payload: /(?:;|\|\||\||&&|`|\$\()\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell|cmd)(?=[\s;|&)`]|$)/i,
    marker: /doc-cmd-separator/i,
    description: /명령 구분자 표기가/i,
  },
]);

// 경보 자체가 웹 공격 후보로 표시됐는지(SIEM 규칙의 MITRE 매핑·위험도). 설명문 문구와 무관하다.
const WEB_EXPLOIT_TECHNIQUE = 'T1190';
const FLAGGED_LEVEL = 5;

function isFlagged(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const level = Number(alert?.rule?.level);
  return mitre.includes(WEB_EXPLOIT_TECHNIQUE) || (Number.isFinite(level) && level >= FLAGGED_LEVEL);
}

function safeDecode(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function readUrl(alert) {
  const url = alert?.data?.url;
  if (typeof url !== 'string' || !url) return '';
  const once = safeDecode(url);
  return [url, once, safeDecode(once)].join('\n');
}

function readCount(alert) {
  const count = Number(alert?.data?.count);
  return Number.isFinite(count) && count >= 0 ? count : 0;
}

export function decide(alert) {
  const url = readUrl(alert);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const repeated = readCount(alert) >= REPEAT_MIN;

  const found = FAMILIES
    .map((f) => ({
      f,
      inUrl: f.payload.test(url) || f.marker.test(url),
      inDescription: f.description.test(description),
    }))
    .filter((m) => m.inUrl || m.inDescription);

  const urlMatches = found.filter((m) => m.inUrl);
  let action = 'record';
  let confidence = 0;
  let reason = '등록 패턴과 일치하지 않음';

  if (urlMatches.length > 0 && repeated) {
    const withDescription = urlMatches.some((m) => m.inDescription);
    action = 'block';
    confidence = withDescription ? 0.95 : 0.9;
    reason = `${urlMatches.map((m) => m.f.name).join(', ')} — 같은 주소에서 ${readCount(alert)}번 반복`;
  } else if (found.length > 0 || isFlagged(alert)) {
    // 막을 만큼 명확하지 않은 웹 공격 후보: 알림(0.5 이상 0.85 미만)
    action = 'alert';
    if (urlMatches.length > 0) {
      confidence = 0.7;
      reason = `${urlMatches.map((m) => m.f.name).join(', ')} — 반복 증거 부족(추가 확인 필요)`;
    } else if (found.length > 0) {
      confidence = 0.65;
      reason = `${found.map((m) => m.f.name).join(', ')} — 설명문 단서만 있고 요청 인자 근거 없음(추가 확인 필요)`;
    } else {
      confidence = 0.6;
      reason = '미확정 단발 신호 — SQL 구문·스크립트 태그·경로 거슬러 올라가기 패턴을 특정할 수 없음';
    }
  }

  // 임계값과 action 이 어긋나지 않게 한 번 더 맞춘다.
  if (action === 'block' && confidence < THRESHOLDS.block) action = 'alert';
  return { action, confidence, reason };
}
