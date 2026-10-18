// xdr/known-cve/decide.mjs
// known-cve 독립 판정기. 전달받은 alert 객체만으로 판정한다.
// (import 없음 / 파일·네트워크 접근 없음 / 공개 함수는 decide 하나)

// ── patterns.json 의 패턴 (xdr/known-cve/patterns.json 을 그대로 옮겨 적음) ──
const PATTERNS = Object.freeze([
  {
    "name": "log4j-jndi-lookup",
    "condition": "data.useragent(fixture에서 확인되는 유일한 요청 머리글 필드) 값 또는 data.url의 쿼리 문자열(요청 인자) 값에, URL 디코딩 후 대소문자 구분 없이 `${jndi:` 다음에 ldap, ldaps, rmi, dns 중 하나와 `://`가 이어지는 JNDI 원격 조회 구문이 포함됨. `jndi` 단어만 있는 값, `CVE-2021-44228` 문자열만 있는 값, 중괄호만 있는 값, 조회 구문이 잘린 조각은 일치로 보지 않는다.",
    "evidence": "CVE-2021-44228은 Log4j가 공격자 제어 문자열의 `${jndi:ldap://...}` 같은 JNDI 조회를 처리해 원격 코드 실행으로 이어질 수 있는 취약점이며, fixture kc-01(data.useragent)과 kc-02(data.url)에 이 구문이 있으나 일치는 악용 시도 신호일 뿐 성공을 뜻하지 않는다."
  },
  {
    "name": "public-facing-app-exploit-attempt",
    "condition": "log4j-jndi-lookup 패턴이 data.useragent 또는 data.url에서 일치함. rule.mitre의 T1190 태그는 구문이 없는 항목(kc-09~kc-16)에도 붙어 있어 조건으로 쓰지 않으며, data.srcip와 agent.name만으로는 요청이 인터넷에 노출된 애플리케이션으로 외부에서 들어왔는지 확인할 수 없어 외부 노출 여부는 조건에 포함하지 않는다.",
    "evidence": "MITRE ATT&CK T1190은 인터넷에 노출된 애플리케이션의 취약점을 악용한 초기 접근 기법이며, 이 패턴은 fixture kc-01~kc-08처럼 알려진 CVE 악용 구문이 요청 필드에 있는 신호만 근거로 삼고 외부 노출은 판단하지 않는다."
  }
]);

const PATTERN_NAME = PATTERNS[0].name; // log4j-jndi-lookup
const EXPLOIT_PATTERN_NAME = PATTERNS[1].name; // public-facing-app-exploit-attempt (조건: log4j-jndi-lookup 일치와 동일)
const CVE_REF = 'CVE-2021-44228';

// 검사 대상 필드: alert.data.useragent, alert.data.url
const FIELDS = ['useragent', 'url'];

// URL 디코딩 후 대소문자 무시: ${jndi: 뒤에 ldap|ldaps|rmi|dns 와 :// 가 이어지는 완전한 구문
const FULL_LOOKUP = /\$\{jndi:(?:ldaps|ldap|rmi|dns):\/\//i;

// 불완전한 단서: jndi 단어, CVE 식별자
const JNDI_WORD = /jndi/i;
const CVE_ID = /\bCVE-\d{4}-\d{4,}\b/i;

// ── 확신도 (action 기준: >=0.85 block, >=0.5 alert, 그 아래 record) ─────────
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

const CONF_FULL_LOOKUP = 0.95; // 완전한 구문. 두 필드가 모두 일치해도 가산하지 않는다.
const CONF_PARTIAL_JNDI = 0.6; // jndi 단어만 있는 불완전한 단서
const CONF_PARTIAL_CVE = 0.55; // CVE 식별자만 있는 불완전한 단서
const CONF_PARTIAL_BOTH = 0.65; // 서로 다른 두 종류의 불완전한 단서가 모두 있는 경우
const CONF_NONE = 0;

// ── 내부 도우미 ───────────────────────────────────────────────────────────
function actionFor(confidence) {
  if (confidence >= BLOCK_THRESHOLD) return 'block';
  if (confidence >= ALERT_THRESHOLD) return 'alert';
  return 'record';
}

// 디코딩 실패(잘못된 % 시퀀스)여도 예외를 밖으로 내보내지 않는다.
// 이중 인코딩을 고려해 최대 2회까지 풀고, 실패하면 그 시점의 값을 그대로 쓴다.
function safeDecode(value) {
  let current = value;
  for (let i = 0; i < 2; i += 1) {
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

function readField(alert, name) {
  const data = alert && typeof alert === 'object' ? alert.data : undefined;
  const raw = data && typeof data === 'object' ? data[name] : undefined;
  return typeof raw === 'string' ? raw : '';
}

export function decide(alert) {
  // 원문과 디코딩본을 모두 검사한다. (원문에 이미 ${jndi:... 가 있는 경우 포함)
  const values = FIELDS.map((name) => {
    const raw = readField(alert, name);
    return { name: `data.${name}`, texts: raw ? [raw, safeDecode(raw)] : [] };
  });

  const matchesIn = (regex) =>
    values.filter((v) => v.texts.some((t) => regex.test(t))).map((v) => v.name);

  const fullFields = matchesIn(FULL_LOOKUP);
  if (fullFields.length > 0) {
    return {
      action: actionFor(CONF_FULL_LOOKUP),
      confidence: CONF_FULL_LOOKUP,
      reason: `${PATTERN_NAME}, ${EXPLOIT_PATTERN_NAME} 일치: ${fullFields.join(', ')}에서 완전한 JNDI 원격 조회 구문 확인(${CVE_REF})`,
    };
  }

  const jndiFields = matchesIn(JNDI_WORD);
  const cveFields = matchesIn(CVE_ID);
  if (jndiFields.length > 0 || cveFields.length > 0) {
    let confidence = CONF_PARTIAL_JNDI;
    if (jndiFields.length > 0 && cveFields.length > 0) confidence = CONF_PARTIAL_BOTH;
    else if (cveFields.length > 0) confidence = CONF_PARTIAL_CVE;
    const clues = [
      jndiFields.length > 0 ? `jndi 단어(${jndiFields.join(', ')})` : null,
      cveFields.length > 0 ? `CVE 식별자(${cveFields.join(', ')})` : null,
    ].filter(Boolean);
    return {
      action: actionFor(confidence),
      confidence,
      reason: `${PATTERN_NAME} 부분 단서: ${clues.join(' + ')}만 있고 완전한 조회 구문 없음`,
    };
  }

  return {
    action: actionFor(CONF_NONE),
    confidence: CONF_NONE,
    reason: '일치하는 패턴 없음: data.useragent, data.url에서 관련 신호 없음',
  };
}
