import { createHash, randomBytes } from 'node:crypto';

// 기기 세션 쿠키. `__Host-` 접두사는 Secure, Path=/, Domain 없음을 브라우저가 강제한다.
export const DEVICE_COOKIE = '__Host-byte-back-device-session';
export const DEVICE_SESSION_TTL_SECONDS = 8 * 60 * 60;
// 등록·인증 챌린지는 생성 시점부터 5분 동안만 유효하다.
export const CHALLENGE_TTL_SECONDS = 5 * 60;

// randomBytes(32)를 base64url로 인코딩하면 정확히 43자다.
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export function generateSessionToken() {
  return randomBytes(32).toString('base64url');
}

// DB에는 원문 토큰이 아니라 SHA-256 해시(16진수 64자)만 저장한다.
export function hashSessionToken(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function readDeviceSessionToken(cookieHeader) {
  if (typeof cookieHeader !== 'string' || cookieHeader.length > 8192) return null;
  const prefix = `${DEVICE_COOKIE}=`;
  const part = cookieHeader
    .split(';')
    .map(item => item.trim())
    .find(item => item.startsWith(prefix));
  const token = part?.slice(prefix.length);
  return typeof token === 'string' && TOKEN_PATTERN.test(token) ? token : null;
}

export function deviceSessionCookie(token, maxAgeSeconds) {
  return `${DEVICE_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

export function clearDeviceSessionCookie() {
  return `${DEVICE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export function isApprovedCredential(row) {
  return Boolean(
    row
    && row.status === 'approved'
    && typeof row.approved_by === 'string' && row.approved_by
    && typeof row.approved_at === 'string' && row.approved_at
  );
}

const deny = (status, error) => Object.freeze({ ok: false, status, error });

// 메모 API가 로그인 검증 직후, 메모 DB 작업 전에 호출한다.
// 조회 오류·예외·형식 불일치는 모두 거부(fail closed)한다.
export async function requireApprovedDevice({
  supabase, login, cookieHeader, now = new Date(),
}) {
  if (login?.kind !== 'student' || typeof login.userId !== 'string' || !login.userId) {
    return deny(403, 'STUDENT_ACCOUNT_REQUIRED');
  }

  const token = readDeviceSessionToken(cookieHeader);
  if (!token) return deny(403, 'DEVICE_APPROVAL_REQUIRED');

  try {
    const sessionResult = await supabase
      .from('device_sessions')
      .select('user_id, credential_id, expires_at, revoked_at')
      .eq('token_hash', hashSessionToken(token))
      .maybeSingle();
    if (sessionResult.error) return deny(503, 'DEVICE_CHECK_UNAVAILABLE');

    const session = sessionResult.data;
    if (!session
        || session.user_id !== login.userId
        || session.revoked_at !== null
        || !(Date.parse(session.expires_at) > now.getTime())
        || typeof session.credential_id !== 'string' || !session.credential_id) {
      return deny(403, 'DEVICE_APPROVAL_REQUIRED');
    }

    const credentialResult = await supabase
      .from('device_credentials')
      .select('user_id, status, approved_by, approved_at')
      .eq('credential_id', session.credential_id)
      .maybeSingle();
    if (credentialResult.error) return deny(503, 'DEVICE_CHECK_UNAVAILABLE');

    const credential = credentialResult.data;
    if (!credential
        || credential.user_id !== login.userId
        || !isApprovedCredential(credential)) {
      return deny(403, 'DEVICE_APPROVAL_REQUIRED');
    }

    return Object.freeze({ ok: true, credentialId: session.credential_id });
  } catch {
    return deny(503, 'DEVICE_CHECK_UNAVAILABLE');
  }
}

// 인증된 사용자·자격 증명에 연결된 새 세션을 저장한다. 저장에 실패하면 null이며,
// 호출자는 이 경우 쿠키를 발급하지 않는다.
export async function issueDeviceSession({
  supabase, userId, credentialId, now = new Date(),
  ttlSeconds = DEVICE_SESSION_TTL_SECONDS, createToken = generateSessionToken,
}) {
  try {
    const token = createToken();
    if (!TOKEN_PATTERN.test(token)) return null;
    const { error } = await supabase.from('device_sessions').insert({
      user_id: userId,
      credential_id: credentialId,
      token_hash: hashSessionToken(token),
      expires_at: new Date(now.getTime() + ttlSeconds * 1000).toISOString(),
    });
    if (error) return null;
    return Object.freeze({ token, maxAgeSeconds: ttlSeconds });
  } catch {
    return null;
  }
}

// 현재 브라우저의 기기 세션 쿠키가 가리키는 DB 세션을 회수한다.
export async function revokeDeviceSessionFromCookie({
  supabase, cookieHeader, now = new Date(),
}) {
  const token = readDeviceSessionToken(cookieHeader);
  if (!token) return 'none';
  try {
    if (!supabase) return 'revoke_failed';
    const { error } = await supabase
      .from('device_sessions')
      .update({ revoked_at: now.toISOString() })
      .eq('token_hash', hashSessionToken(token))
      .is('revoked_at', null);
    return error ? 'revoke_failed' : 'revoked';
  } catch {
    return 'revoke_failed';
  }
}
