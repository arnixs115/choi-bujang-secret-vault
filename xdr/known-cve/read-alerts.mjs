
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../fixtures/known-cve.json');

const SECRET_ASSIGNMENT =
  /\b(password|passwd|token|secret|api[_-]?key|authorization|cookie|credential)\b\s*[:=]\s*[^\s,;]+/gi;
const BEARER_TOKEN = /\bBearer\s+[^\s,;]+/gi;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const JWT =
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

function safeText(value, fallback = '없음') {
  if (typeof value !== 'string' || value.trim() === '') {
    return fallback;
  }

  return value
    .replace(SECRET_ASSIGNMENT, '$1=[숨김]')
    .replace(BEARER_TOKEN, 'Bearer [숨김]')
    .replace(EMAIL, '[이메일 숨김]')
    .replace(JWT, '[토큰 숨김]')
    .replace(/[\r\n\t]+/g, ' ')
    .slice(0, 240);
}

function safeSourceIp(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return '없음';
  }

  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-f:]+$/i;

  return ipv4.test(value) ||
    (value.includes(':') && ipv6.test(value))
    ? value
    : '[숨김]';
}

function safeAccount(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    return '없음';
  }

  return /^[A-Za-z0-9._@-]{1,64}$/.test(value)
    ? value
    : '[숨김]';
}

export function extractAlerts(fixture) {
  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1' ||
    fixture.moduleKey !== 'known-cve' ||
    !Array.isArray(fixture.alerts)
  ) {
    throw new Error('known-cve 경보 묶음 형식이 아닙니다.');
  }

  const rows = fixture.alerts.map((alert) => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeSourceIp(alert?.data?.srcip),
    account: safeAccount(
      alert?.data?.srcuser ?? alert?.data?.user
    ),
    ruleLevel: Number.isFinite(alert?.rule?.level)
      ? alert.rule.level
      : '없음',
    description: safeText(alert?.rule?.description),
  }));

  if (rows.length !== fixture.alerts.length) {
    throw new Error('경보 건수와 추출한 줄 수가 일치하지 않습니다.');
  }

  return rows;
}

export async function readAlerts() {
  const fixture = JSON.parse(
    await readFile(fixturePath, 'utf8')
  );

  return {
    alertCount: fixture.alerts?.length ?? 0,
    rows: extractAlerts(fixture),
  };
}

// 독립 확인용 모듈이며 decide.mjs에서는 불러오지 않습니다.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const { alertCount, rows } = await readAlerts();

    console.log(`경보 건수: ${alertCount}`);
    console.log(`추출 줄 수: ${rows.length}`);

    for (const row of rows) {
      console.log([
        `시각=${row.timestamp}`,
        `출발 주소=${row.sourceAddress}`,
        `계정=${row.account}`,
        `규칙 수준=${row.ruleLevel}`,
        `설명=${row.description}`,
      ].join(' | '));
    }

    if (alertCount !== rows.length) {
      process.exitCode = 1;
    }
  } catch {
    console.error(
      '경보 읽기에 실패했습니다. 원본 경보 내용은 출력하지 않았습니다.'
    );
    process.exitCode = 1;
  }
}
