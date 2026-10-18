// 시험 전용 가상 배포. 실제 서버가 아니며, 이 파일의 응답은 실측 결과가 아니다.
// api/notes.js, api/notes/[id].js, api/notes/[id]/restore.js, api/auth/login.js,
// src/device-handlers.mjs 가 돌려주는 상태 코드·오류 코드·헤더를 같은 모양으로 흉내 낸다.
export const SAMPLE_MARKER = 'SAMPLE_NOTE_1';
export const TEST_LOGIN_TOKEN = 'testheader.testpayload.testsignature';
export const TEST_DEVICE_TOKEN = 'D'.repeat(43);
export const SECRET_NOTE_ID = '11111111-2222-4333-8444-555555555555';
export const SECRET_NOTE_TITLE = 'SECRET_TITLE_DO_NOT_RECORD';
export const SECRET_NOTE_BODY = 'SECRET_BODY_DO_NOT_RECORD';
export const SECRET_SET_COOKIE = '__Host-byte-back-session=SECRET_COOKIE_VALUE; Path=/; HttpOnly';
export const VERCEL_ID = 'icn1::sfo1::abcde-1700000000000-0123456789ab';

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const NOTE_ID = new RegExp(`^/api/notes/${UUID}$`, 'iu');
const RESTORE = new RegExp(`^/api/notes/${UUID}/restore$`, 'iu');

// options.requestId: false 이면 x-vercel-id 헤더를 보내지 않는다.
// options.deviceSessionValid: false 이면 기기 세션 쿠키를 받아도 승인하지 않는다.
// options.overrides: { 'METHOD /path': () => Response } 로 특정 응답을 바꾼다.
export function createFakeDeployment(options = {}) {
  const { requestId = true, deviceSessionValid = true, overrides = {} } = options;
  const calls = [];

  function json(status, body, extra = {}) {
    const headers = {
      'content-type': 'application/json; charset=utf-8',
      'x-content-type-options': 'nosniff',
      'set-cookie': SECRET_SET_COOKIE, // 점검기가 절대 기록하면 안 되는 헤더
      ...extra,
    };
    if (requestId) headers['x-vercel-id'] = VERCEL_ID;
    return new Response(JSON.stringify(body), { status, headers });
  }
  const api = (status, body, extra) => json(status, body, { 'cache-control': 'no-store', ...extra });

  function route(url, init) {
    const { pathname } = new URL(url);
    const method = init.method ?? 'GET';
    const cookie = init.headers?.cookie ?? '';
    const origin = init.headers?.origin;
    const hasLogin = cookie.includes(TEST_LOGIN_TOKEN);
    const hasDevice = deviceSessionValid && cookie.includes(TEST_DEVICE_TOKEN);
    const foreign = typeof origin === 'string' && !origin.startsWith('https://student-defense.vercel.app');
    const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    const key = `${method} ${pathname}`;
    for (const [pattern, make] of Object.entries(overrides)) {
      if (key === pattern) return make();
    }

    if (pathname === '/data.json') {
      return json(200, { sampleMarker: SAMPLE_MARKER, notes: [{ title: '가상 메모' }] });
    }
    if (pathname === '/') return json(200, {}, { 'content-type': 'text/html; charset=utf-8' });
    if (pathname === '/aleph.json') return json(200, { schema: 'aleph.defense.deployment.v1' });

    if (pathname === '/api/auth/login') {
      if (method !== 'POST') return api(405, { error: 'METHOD_NOT_ALLOWED' });
      if (foreign || !origin) return api(403, { error: 'INVALID_ORIGIN' });
      return api(400, { error: 'INVALID_LOGIN_INPUT' });
    }

    if (pathname.startsWith('/api/device/')) {
      if (method !== 'POST') return api(405, { error: 'METHOD_NOT_ALLOWED' }, { allow: 'POST' });
      if (foreign || !origin) return api(403, { error: 'INVALID_ORIGIN' });
      if (!hasLogin) return api(401, { error: 'UNAUTHORIZED' });
      if (pathname === '/api/device/status') {
        return api(200, hasDevice
          ? { state: 'session_valid', memoAccess: true, canRegister: false, canAuthenticate: false }
          : { state: 'auth_required', memoAccess: false, canRegister: false, canAuthenticate: true });
      }
      return api(400, { error: 'INVALID_AUTHENTICATION_RESPONSE' });
    }

    if (pathname === '/api/notes' || NOTE_ID.test(pathname)) {
      const byId = pathname !== '/api/notes';
      const allowed = byId ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
      if (!allowed.includes(method)) return api(405, { error: 'METHOD_NOT_ALLOWED' });
      if (mutating && (foreign || !origin)) return api(403, { error: 'INVALID_ORIGIN' });
      if (!hasLogin) return api(401, { error: 'UNAUTHORIZED' });
      if (!hasDevice) return api(403, { error: 'DEVICE_APPROVAL_REQUIRED' });
      if (byId) return api(200, { id: pathname.split('/').pop(), title: SECRET_NOTE_TITLE, body: SECRET_NOTE_BODY });
      return api(200, [{ id: SECRET_NOTE_ID, title: SECRET_NOTE_TITLE, body: SECRET_NOTE_BODY }]);
    }

    if (RESTORE.test(pathname)) {
      if (method !== 'POST') return api(405, { error: 'METHOD_NOT_ALLOWED' });
      if (foreign || !origin) return api(403, { error: 'INVALID_ORIGIN' });
      if (!hasLogin) return api(401, { error: 'UNAUTHORIZED' });
      return api(400, { error: 'INVALID_RESTORE_REQUEST' });
    }

    // 없는 경로: 호스팅 기본 404(JSON이 아님)
    return new Response('The page could not be found', {
      status: 404, headers: { 'content-type': 'text/plain', ...(requestId ? { 'x-vercel-id': VERCEL_ID } : {}) },
    });
  }

  async function fetch(url, init = {}) {
    calls.push({ url: String(url), method: init.method ?? 'GET', headers: { ...init.headers } });
    return route(url, init);
  }
  return { fetch, calls };
}
