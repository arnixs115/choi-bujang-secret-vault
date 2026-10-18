// XDR 웹 주입 임시 거부 규칙 저장소 (JSON 파일).
// 파일 입출력 오류(io_error)와 규칙 자체/저장소 내용 문제(registration_failed)를 구분한다.
import { promises as fs } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_RULES_PATH = path.resolve(here, 'deny-rules.json');

export class RuleStoreError extends Error {
  constructor(kind, message, cause) {
    super(message);
    this.name = 'RuleStoreError';
    this.kind = kind; // 'io_error' | 'registration_failed'
    if (cause) this.cause = cause;
  }
}

/** 유효한 IPv4/IPv6 문자열만 정규화해서 돌려주고, 아니면 null. */
export function normalizeIp(value) {
  if (typeof value !== 'string') return null;
  let ip = value.trim();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  const family = net.isIP(ip);
  if (!family) return null;
  return family === 6 ? ip.toLowerCase() : ip;
}

/** 자기 자신/전파 불가 주소를 막아 자해성 차단을 방지한다. 사설 대역은 막지 않는다. */
export function isBlockableIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    return true;
  }
  if (ip === '::' || ip === '::1') return false;
  if (/^fe[89ab]/.test(ip) || /^ff/.test(ip)) return false;
  return true;
}

export function isActive(rule, now) {
  const t = Date.parse(rule?.expiresAt);
  return Number.isFinite(t) && t > now;
}

export function activeRules(rules, now) {
  return rules.filter((r) => isActive(r, now));
}

export async function readRules(rulesPath = DEFAULT_RULES_PATH) {
  let text;
  try {
    text = await fs.readFile(rulesPath, 'utf8');
  } catch (err) {
    if (err?.code === 'ENOENT') return [];
    throw new RuleStoreError('io_error', `규칙 파일을 읽지 못했습니다: ${err?.code ?? err?.message}`, err);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new RuleStoreError('registration_failed', '규칙 파일 JSON이 손상되었습니다.', err);
  }
  if (!parsed || !Array.isArray(parsed.rules)) {
    throw new RuleStoreError('registration_failed', '규칙 파일 형식이 올바르지 않습니다(rules 배열 없음).');
  }
  return parsed.rules;
}

async function writeRules(rules, rulesPath) {
  const tmp = `${rulesPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await fs.writeFile(tmp, JSON.stringify({ version: 1, rules }, null, 2) + '\n', 'utf8');
    await fs.rename(tmp, rulesPath);
  } catch (err) {
    await fs.rm(tmp, { force: true }).catch(() => {});
    throw new RuleStoreError('io_error', `규칙 파일을 쓰지 못했습니다: ${err?.code ?? err?.message}`, err);
  }
}

let chain = Promise.resolve(); // 같은 프로세스 안의 동시 쓰기를 순서대로 처리

/** 같은 IP의 활성 규칙이 있으면 새로 만들지 않는다. 만료된 규칙은 저장 시 정리한다. */
export function addRule(rule, { rulesPath = DEFAULT_RULES_PATH, now = Date.now() } = {}) {
  const run = async () => {
    const existing = await readRules(rulesPath);
    const active = activeRules(existing, now);
    const duplicate = active.find((r) => r.sourceIp === rule.sourceIp);
    if (duplicate) return { added: false, duplicate };
    await fs.mkdir(path.dirname(rulesPath), { recursive: true }).catch((err) => {
      throw new RuleStoreError('io_error', `규칙 폴더를 만들지 못했습니다: ${err?.code ?? err?.message}`, err);
    });
    await writeRules([...active, rule], rulesPath);
    return { added: true, rule };
  };
  const result = chain.then(run, run);
  chain = result.catch(() => {});
  return result;
}
