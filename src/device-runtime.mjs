import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createDeviceHandlers } from './device-handlers.mjs';
import { createLoginVerifier } from './verify-login.mjs';

// api/device/*.js 다섯 파일이 공유하는 서버 설정. api/ 안의 파일은 모두 함수가 되므로
// 공통 코드는 src/ 에 둔다. 환경 변수는 요청이 올 때 읽어, 설정이 빠져도 모듈 로드가 죽지 않는다.
let verifier = null;

function verifyLogin(authorization, cookieHeader) {
  verifier ??= createLoginVerifier({
    config,
    supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
  });
  return verifier(authorization, cookieHeader);
}

function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return null;
  return createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export const deviceHandlers = createDeviceHandlers({ verifyLogin, getSupabase, config });
