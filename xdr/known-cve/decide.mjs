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

// 애매한 악용 단서(요청 필드에 실제로 있는 구문 조각만 사용한다):
//  - `${jndi:` 로 시작하지만 완전한 구문은 아닌 조회 (스킴 없음, `://` 없음, 허용 목록 밖 스킴 등)
//  - `lookup-fragment` 처럼 잘린 조회를 나타내는 명시적 요청 필드 값
//  - `${` 없이 `jndi:ldap://` 같은 JNDI 원격 주소 형태만 있는 경우
const PARTIAL_LOOKUP = /\$\{\s*jndi\s*:|\blookup-fragment\b/i;
const BARE_JNDI_URL = /\bjndi:(?:ldaps|ldap|rmi|dns):\/\//i;

// 단어·식별자만 있는 값은 판정 근거로 쓰지 않는다. reason 에 "제외했다"는 참고만 남긴다.
const WEAK_JNDI_WORD = /jndi/i;
const WEAK_CVE_ID = /\bCVE-\d{4}-\d{4,}\b/i;

// fixture 에서 확인된 수업용 점검 경로만 신호로 삼는다.
// 임의의 `/tools/` 아래 check 포함 경로만으로 점검 도구라고 판단하지 않는다.
// (data.useragent 나 쿼리 안의 문자열에는 적용하지 않는다.)
const TOOL_PATH_SIGNALS = Object.freeze([
  { name: 'class-check-path', regex: /^\/tools\/class-check\/?$/i },
]);

// ── 확신도 (action 기준: >=0.85 block, >=0.5 alert, 그 아래 record) ─────────
const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

const CONF_FULL_LOOKUP = 0.95; // 완전한 구문. 두 필드가 모두 일치해도 가산하지 않는다.
const CONF_PARTIAL_LOOKUP = 0.6; // `${jndi:` 로 시작하는 불완전한 조회 구문
const CONF_BARE_JNDI_URL = 0.55; // `${` 없이 jndi:스킴:// 형태만 있는 경우
const CONF_TOOL_PATH = 0.5; // fixture 에 명시된 수업용 점검 경로
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
  // rule.description / rule.mitre / rule.level / data.srcip 는 읽지 않는다.
  const values = FIELDS.map((name) => {
    const raw = readField(alert, name);
    return { name: `data.${name}`, texts: raw ? [raw, safeDecode(raw)] : [] };
  });

  const matchesIn = (regex) =>
    values.filter((v) => v.texts.some((t) => regex.test(t))).map((v) => v.name);

  // 1) 명확한 공격: 완전한 JNDI 원격 조회 구문
  const fullFields = matchesIn(FULL_LOOKUP);
  if (fullFields.length > 0) {
    return {
      action: actionFor(CONF_FULL_LOOKUP),
      confidence: CONF_FULL_LOOKUP,
      reason: `${PATTERN_NAME}, ${EXPLOIT_PATTERN_NAME} 일치: ${fullFields.join(', ')}에서 완전한 JNDI 원격 조회 구문 확인(${CVE_REF})`,
    };
  }

  // 2) 애매한 악용·점검 흔적: 실제 요청 필드의 불완전한 조회 조각 또는 fixture 확인 경로
  const partialFields = matchesIn(PARTIAL_LOOKUP);
  const bareFields = matchesIn(BARE_JNDI_URL);
  const urlValue = values.find((v) => v.name === 'data.url');
  const toolHits = TOOL_PATH_SIGNALS
    .filter((sig) => urlValue && urlValue.texts.some((t) => sig.regex.test(t.split(/[?#]/)[0])))
    .map((sig) => sig.name);

  if (partialFields.length > 0 || bareFields.length > 0 || toolHits.length > 0) {
    let confidence = CONF_NONE;
    const signals = [];
    if (partialFields.length > 0) {
      confidence = Math.max(confidence, CONF_PARTIAL_LOOKUP);
      signals.push(`${PATTERN_NAME} 불완전한 조회 조각(${partialFields.join(', ')})`);
    }
    if (bareFields.length > 0) {
      confidence = Math.max(confidence, CONF_BARE_JNDI_URL);
      signals.push(`${PATTERN_NAME} jndi 원격 주소 형태(${bareFields.join(', ')})`);
    }
    if (toolHits.length > 0) {
      confidence = Math.max(confidence, CONF_TOOL_PATH);
      signals.push(`${toolHits.join(', ')}(fixture 에서 확인된 data.url 경로)`);
    }
    return {
      action: actionFor(confidence),
      confidence,
      reason: `부분 신호: ${signals.join(' + ')}; 완전한 JNDI 조회 구문은 없음`,
    };
  }

  // 3) 정상 이벤트: 기록만. jndi 단어나 CVE 식별자만 있는 값은 근거에서 제외한다.
  const weak = [];
  if (matchesIn(WEAK_JNDI_WORD).length > 0) weak.push('jndi 단어');
  if (matchesIn(WEAK_CVE_ID).length > 0) weak.push('CVE 식별자');
  const note = weak.length > 0 ? ` (${weak.join(', ')}만 있어 판정 근거에서 제외)` : '';
  return {
    action: actionFor(CONF_NONE),
    confidence: CONF_NONE,
    reason: `일치하는 패턴 없음: data.useragent, data.url에서 악용 구문·점검형 도구 경로 없음${note}`,
  };
}
