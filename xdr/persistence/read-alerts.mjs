import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURE = join(
  MODULE_DIR,
  '..',
  'fixtures',
  'persistence.json',
);

function redact(value) {
  return String(value ?? '')
    .replace(/\b(Bearer\s+)\S+/giu, '$1[REDACTED]')
    .replace(
      /\b(password|passwd|pwd|token|secret|api[_ -]?key|access[_ -]?key|private[_ -]?key)\b(\s*[:=]\s*)[^\s,;]+/giu,
      '$1$2[REDACTED]',
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
      '[REDACTED]',
    )
    .replace(/\b(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9_-]{48,})\b/gu, '[REDACTED]')
    .replace(/[\r\n\u2028\u2029]+/gu, ' ')
    .slice(0, 500);
}

function safeField(value, fallback = 'unknown') {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  return redact(value);
}

export function extractAlert(alert) {
  return {
    timestamp: safeField(alert?.timestamp),
    sourceAddress: safeField(alert?.data?.srcip),
    account: safeField(alert?.data?.srcuser),
    ruleLevel: safeField(alert?.rule?.level),
    description: safeField(alert?.rule?.description),
  };
}

export async function readAlerts(fixturePath = DEFAULT_FIXTURE) {
  const raw = await readFile(fixturePath, 'utf8');
  const fixture = JSON.parse(raw);

  if (
    fixture?.schema !== 'aleph.xdr.fixture.v1' ||
    fixture?.moduleKey !== 'persistence' ||
    !Array.isArray(fixture.alerts)
  ) {
    throw new Error('persistence 경보 묶음 형식이 아닙니다.');
  }

  return fixture.alerts.map(extractAlert);
}

async function main() {
  const fixturePath = process.argv[2]
    ? resolve(process.argv[2])
    : DEFAULT_FIXTURE;

  const rows = await readAlerts(fixturePath);

  // stdout에는 경보별 JSON 한 줄만 출력한다.
  for (const row of rows) {
    process.stdout.write(`${JSON.stringify(row)}\n`);
  }
}

const invokedPath = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : '';

if (invokedPath === import.meta.url) {
  main().catch(() => {
    process.stderr.write(
      'persistence 경보를 읽지 못했습니다. 입력 파일 형식과 경로를 확인하세요.\n',
    );
    process.exitCode = 1;
  });
}