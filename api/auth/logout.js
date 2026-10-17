import { createClient } from '@supabase/supabase-js';
import { hasSameOrigin } from '../../src/verify-origin.mjs';
import {
  clearDeviceSessionCookie,
  readDeviceSessionToken,
  revokeDeviceSessionFromCookie,
} from '../../src/device-session.mjs';

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    response.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
    });
    return;
  }

  if (!hasSameOrigin(request)) {
    response.status(403).json({
      error: 'INVALID_ORIGIN',
    });
    return;
  }

  // 로그인 쿠키와 기기 세션 쿠키를 모두 지운다. 쿠키는 DB 회수 결과와 상관없이 지운다.
  response.setHeader('Set-Cookie', [
    '__Host-byte-back-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
    clearDeviceSessionCookie(),
  ]);

  // 현재 브라우저의 기기 세션을 DB에서도 회수한다.
  const cookieHeader = request.headers.cookie;
  const revoked = readDeviceSessionToken(cookieHeader)
    ? await revokeDeviceSessionFromCookie({
        supabase: getSupabase(),
        cookieHeader,
      })
    : 'none';

  if (revoked === 'revoke_failed') {
    response.status(500).json({
      error: 'DEVICE_SESSION_REVOKE_FAILED',
    });
    return;
  }

  response.status(200).json({
    ok: true,
  });
}
