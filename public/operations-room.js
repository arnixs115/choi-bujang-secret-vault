// 작전실: 점검기(`npm run attack:results`)가 실제로 요청을 보내 만든 /attack-results.json만 그대로 보여 줍니다.
// 이 화면은 요청을 보내지 않고, 결과를 계산해 채우거나 추정하지 않습니다.
// 파일이 없거나 형식이 맞지 않으면 숫자를 하나도 보여 주지 않고 "결과 없음"으로 표시합니다.
// 미실행(not_run)과 미확인(unverified)은 요청을 보내지 않은 시험이므로 성공으로 세지 않습니다.
export const RESULTS_URL = '/attack-results.json';
export const RESULTS_SCHEMA = 'aleph.attack-results.v1';
export const STATUS_LABEL = Object.freeze({
  pass: '통과', fail: '실패', not_run: '미실행', unverified: '미확인',
});
const SENT = ['pass', 'fail'];
const RESPONSE_FIELDS = ['httpStatus', 'errorCode', 'headers', 'requestId', 'requestIdSource', 'checkedAt', 'observed'];

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// 결과 파일을 읽을 수 있는 모양인지 확인한다. 하나라도 어긋나면 파일 전체를 쓰지 않는다.
export function readResults(data) {
  if (!isObject(data) || data.schema !== RESULTS_SCHEMA) return { ok: false, reason: '결과 파일 형식이 아닙니다.' };
  if (typeof data.generatedAt !== 'string' || !Number.isFinite(Date.parse(data.generatedAt))) {
    return { ok: false, reason: '결과 파일에 생성 시각이 없습니다.' };
  }
  if (!Array.isArray(data.records) || data.records.length === 0) return { ok: false, reason: '결과 파일에 시험 기록이 없습니다.' };
  for (const record of data.records) {
    if (!isObject(record) || typeof record.testId !== 'string' || !(record.status in STATUS_LABEL)) {
      return { ok: false, reason: '시험 기록 형식이 올바르지 않습니다.' };
    }
    if (!SENT.includes(record.status) && RESPONSE_FIELDS.some((key) => record[key] !== null)) {
      return { ok: false, reason: `${record.testId}: 보내지 않은 시험에 응답 값이 있어 결과를 쓰지 않습니다.` };
    }
    if (record.status === 'pass' && !Number.isInteger(record.httpStatus)) {
      return { ok: false, reason: `${record.testId}: 응답 없이 통과로 적힌 기록이 있어 결과를 쓰지 않습니다.` };
    }
  }
  return { ok: true, generatedAt: data.generatedAt, records: data.records };
}

// 파일에 있는 기록의 상태별 개수를 센다. measured는 실제로 요청을 보낸 pass+fail뿐이다.
export function countStatuses(records) {
  const counts = { total: records.length, pass: 0, fail: 0, not_run: 0, unverified: 0 };
  for (const record of records) counts[record.status] += 1;
  return { ...counts, measured: counts.pass + counts.fail };
}

// 한 시험을 화면에 쓸 문자열로 바꾼다. 없는 값은 '없음'이나 '—'로 두고 채우지 않는다.
export function describeRecord(record) {
  const sent = SENT.includes(record.status);
  return {
    id: `${record.stage ?? '?'}단계 · ${record.testId}`,
    route: `${record.method ?? '?'} ${record.path ?? '?'}`,
    status: STATUS_LABEL[record.status],
    http: sent && Number.isInteger(record.httpStatus) ? String(record.httpStatus) : '—',
    requestId: sent ? (record.requestId ?? '없음') : '—',
    checkedAt: sent ? (record.checkedAt ?? '—') : '—',
    note: record.status === 'pass' ? '' : (record.reason ?? ''),
  };
}

function cell(tag, text) {
  const element = document.createElement(tag);
  element.textContent = text; // 항상 textContent로만 넣는다
  return element;
}

function renderResults(root, { generatedAt, records }) {
  const counts = countStatuses(records);
  root.querySelector('#ops-status').textContent =
    `점검기가 ${generatedAt}에 만든 결과 파일입니다. 심판의 판정이 아니라 학생 자신의 점검입니다.`;
  const summary = root.querySelector('#ops-summary');
  summary.replaceChildren(
    cell('li', `실제로 요청을 보낸 시험 ${counts.measured}개: 통과 ${counts.pass} · 실패 ${counts.fail}`),
    cell('li', `미실행 ${counts.not_run} · 미확인 ${counts.unverified} (요청을 보내지 않았으며 성공으로 세지 않음)`),
    cell('li', `전체 시험 ${counts.total}개`),
  );
  summary.hidden = false;
  const body = root.querySelector('#ops-rows');
  body.replaceChildren(...records.map((record) => {
    const view = describeRecord(record);
    const row = document.createElement('tr');
    row.append(cell('td', view.id), cell('td', view.route), cell('td', view.status), cell('td', view.http),
      cell('td', view.requestId), cell('td', view.checkedAt), cell('td', view.note));
    return row;
  }));
  root.querySelector('#ops-table').hidden = false;
}

function renderNoResults(root, message) {
  root.querySelector('#ops-status').textContent = message;
  root.querySelector('#ops-summary').hidden = true;
  root.querySelector('#ops-table').hidden = true;
}

export async function mount() {
  const root = document.querySelector('#operations-room');
  if (!root) return;
  try {
    const response = await fetch(RESULTS_URL, { cache: 'no-store', credentials: 'omit' });
    if (!response.ok) {
      renderNoResults(root, '실행한 점검 결과가 없습니다. 아직 실제로 요청을 보낸 결과 파일이 배포되지 않았습니다.');
      return;
    }
    const parsed = readResults(await response.json());
    if (!parsed.ok) {
      renderNoResults(root, `점검 결과를 표시하지 않습니다. ${parsed.reason}`);
      return;
    }
    renderResults(root, parsed);
  } catch {
    renderNoResults(root, '점검 결과를 읽지 못했습니다. 숫자를 표시하지 않습니다.');
  }
}

if (typeof document !== 'undefined') mount();
