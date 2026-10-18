
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const REDACTED = '[REDACTED]';

const SECRET_ASSIGNMENT =
  /\b(password|passwd|pwd|secret|token|api[\s_-]?key|authorization|cookie|private[\s_-]?key)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi;
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

function safeText(value) {
  if (value === null || value === undefined || value === '') return '-';

  return String(value)
    .replace(SECRET_ASSIGNMENT, (_match, label) => `${label}=${REDACTED}`)
    .replace(BEARER_TOKEN, `Bearer ${REDACTED}`)
    .replace(JWT, REDACTED);
}

export async function readAlerts({ root = ROOT } = {}) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'web-injection.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1' ||
    fixture.moduleKey !== 'web-injection' ||
    !Array.isArray(fixture.alerts)
  ) {
    throw new Error('web_injection_fixture_format_invalid');
  }

  const rows = fixture.alerts.map((alert) => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: safeText(alert?.rule?.level),
    description: safeText(alert?.rule?.description),
  }));

  if (rows.length !== fixture.alerts.length) {
    throw new Error('web_injection_alert_row_count_mismatch');
  }

  return rows;
}

const isMain =
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  try {
    const rows = await readAlerts();

    for (const row of rows) {
      console.log(JSON.stringify(row));
    }

    console.log(`경보 ${rows.length}건 / 추출 ${rows.length}줄`);
  } catch {
    console.error('경보 읽기에 실패했습니다. fixture 형식과 경로를 확인하세요.');
    process.exitCode = 1;
  }
}
