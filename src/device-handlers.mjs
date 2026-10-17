import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { hasSameOrigin } from './verify-origin.mjs';
import {
  CHALLENGE_TTL_SECONDS,
  deviceSessionCookie,
  isApprovedCredential,
  issueDeviceSession,
  requireApprovedDevice,
} from './device-session.mjs';

const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const KNOWN_TRANSPORTS = new Set([
  'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb',
]);

function relyingParty(config) {
  const url = new URL(config.publicAppUrl);
  // RP ID와 기대 출처는 요청 헤더가 아니라 배포 설정에서만 가져온다.
  return { rpID: url.hostname, origin: url.origin, rpName: 'BYTE BACK 자료실' };
}

function transportsOf(value) {
  return Array.isArray(value)
    ? value.filter(item => typeof item === 'string' && KNOWN_TRANSPORTS.has(item))
    : [];
}

function cleanDeviceName(value) {
  if (typeof value !== 'string') return null;
  const name = value.replace(/[\u0000-\u001f\u007f]/gu, ' ').replace(/\s+/gu, ' ').trim();
  return name ? name.slice(0, 60) : null;
}

function boundedString(value, max) {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

// 브라우저가 보낸 JSON을 SimpleWebAuthn에 넘기기 전에 모양과 길이만 거른다.
// 서명·챌린지·출처·RP ID 검증은 SimpleWebAuthn이 한다.
function registrationShape(response) {
  const inner = response?.response;
  return Boolean(
    response && typeof response === 'object' && !Array.isArray(response)
    && response.type === 'public-key'
    && boundedString(response.id, 1024) && BASE64URL.test(response.id)
    && boundedString(response.rawId, 1024) && response.rawId === response.id
    && inner && typeof inner === 'object'
    && boundedString(inner.clientDataJSON, 8192)
    && boundedString(inner.attestationObject, 16384)
  );
}

function authenticationShape(response) {
  const inner = response?.response;
  return Boolean(
    response && typeof response === 'object' && !Array.isArray(response)
    && response.type === 'public-key'
    && boundedString(response.id, 1024) && BASE64URL.test(response.id)
    && boundedString(response.rawId, 1024) && response.rawId === response.id
    && inner && typeof inner === 'object'
    && boundedString(inner.clientDataJSON, 8192)
    && boundedString(inner.authenticatorData, 8192)
    && boundedString(inner.signature, 8192)
    && (inner.userHandle === undefined || inner.userHandle === null
      || boundedString(inner.userHandle, 1024))
  );
}

// 챌린지 행을 찾는 열쇠로만 clientDataJSON의 challenge를 읽는다.
// 신뢰는 DB 행(사용자·용도·만료·미소비)이 결정하고, 서명 검증은 따로 한다.
function challengeFromClientData(clientDataJSON, expectedType) {
  try {
    const parsed = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
    if (parsed?.type !== expectedType || typeof parsed.challenge !== 'string'
        || !/^[A-Za-z0-9_-]{16,256}$/u.test(parsed.challenge)) return null;
    return parsed.challenge;
  } catch {
    return null;
  }
}

export function createDeviceHandlers({ verifyLogin, getSupabase, config, now = () => new Date() }) {
  const rp = relyingParty(config);

  function send(response, status, body) {
    response.status(status).json(body);
  }

  // 모든 기기 API가 공유하는 입구: 메서드, 동일 출처, 로그인, 학생 계정, DB 설정.
  async function guard(request, response) {
    response.setHeader('Cache-Control', 'no-store');

    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      send(response, 405, { error: 'METHOD_NOT_ALLOWED' });
      return null;
    }
    if (!hasSameOrigin(request)) {
      send(response, 403, { error: 'INVALID_ORIGIN' });
      return null;
    }

    let login = null;
    try {
      login = await verifyLogin(request.headers.authorization, request.headers.cookie);
    } catch {
      login = null;
    }
    if (!login) {
      send(response, 401, { error: 'UNAUTHORIZED' });
      return null;
    }
    // 심판 토큰은 학생 계정의 기기 등록·인증에 쓸 수 없다.
    if (login.kind !== 'student') {
      send(response, 403, { error: 'STUDENT_ACCOUNT_REQUIRED' });
      return null;
    }

    let supabase = null;
    try {
      supabase = getSupabase();
    } catch {
      supabase = null;
    }
    if (!supabase) {
      send(response, 500, { error: 'SUPABASE_SERVER_CONFIG_MISSING' });
      return null;
    }
    return { login, supabase };
  }

  async function storeChallenge(supabase, userId, challenge, purpose) {
    const current = now();
    const { error } = await supabase.from('device_challenges').insert({
      user_id: userId,
      challenge,
      purpose,
      expires_at: new Date(current.getTime() + CHALLENGE_TTL_SECONDS * 1000).toISOString(),
    });
    return !error;
  }

  // 한 번의 UPDATE로 "내 것, 이 용도, 아직 안 쓰임, 아직 안 만료"를 모두 확인하며 소비한다.
  // 동시에 같은 챌린지를 쓰는 두 요청 중 한 쪽만 행을 돌려받는다.
  async function consumeChallenge(supabase, userId, challenge, purpose) {
    const current = now().toISOString();
    try {
      const { data, error } = await supabase
        .from('device_challenges')
        .update({ consumed_at: current })
        .eq('user_id', userId)
        .eq('challenge', challenge)
        .eq('purpose', purpose)
        .is('consumed_at', null)
        .gt('expires_at', current)
        .select('id');
      if (error) return 'unavailable';
      return Array.isArray(data) && data.length === 1 ? 'consumed' : 'invalid';
    } catch {
      return 'unavailable';
    }
  }

  async function status(request, response) {
    const context = await guard(request, response);
    if (!context) return;
    const { login, supabase } = context;

    const device = await requireApprovedDevice({
      supabase, login, cookieHeader: request.headers.cookie, now: now(),
    });
    if (device.ok) {
      send(response, 200, {
        state: 'session_valid', memoAccess: true, canRegister: false, canAuthenticate: false,
      });
      return;
    }
    if (device.status === 503) {
      send(response, 503, { error: device.error });
      return;
    }

    const { data, error } = await supabase
      .from('device_credentials')
      .select('status, approved_by, approved_at')
      .eq('user_id', login.userId);
    if (error || !Array.isArray(data)) {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }

    let state;
    if (data.some(isApprovedCredential)) state = 'auth_required';
    else if (data.some(row => row.status === 'pending' || row.status === 'approved')) state = 'pending';
    else if (data.some(row => row.status === 'revoked')) state = 'revoked';
    else if (data.some(row => row.status === 'rejected')) state = 'rejected';
    else state = 'not_registered';

    send(response, 200, {
      state,
      memoAccess: false,
      canAuthenticate: state === 'auth_required',
      canRegister: ['not_registered', 'rejected', 'revoked'].includes(state),
    });
  }

  async function registerOptions(request, response) {
    const context = await guard(request, response);
    if (!context) return;
    const { login, supabase } = context;

    const existing = await supabase
      .from('device_credentials')
      .select('credential_id, transports')
      .eq('user_id', login.userId);
    if (existing.error || !Array.isArray(existing.data)) {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }

    const options = await generateRegistrationOptions({
      rpName: rp.rpName,
      rpID: rp.rpID,
      userName: `byte-back-${login.userId.slice(0, 8)}`,
      userDisplayName: '자료실 학생 계정',
      userID: new TextEncoder().encode(login.userId),
      attestationType: 'none',
      excludeCredentials: existing.data.map(row => ({
        id: row.credential_id, transports: transportsOf(row.transports),
      })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    });

    // 챌린지를 저장하지 못하면 옵션도 내보내지 않는다.
    if (!await storeChallenge(supabase, login.userId, options.challenge, 'registration')) {
      send(response, 500, { error: 'DEVICE_CHALLENGE_STORE_FAILED' });
      return;
    }
    send(response, 200, options);
  }

  async function registerVerify(request, response) {
    const context = await guard(request, response);
    if (!context) return;
    const { login, supabase } = context;

    const body = request.body;
    const registration = body?.response;
    if (!registrationShape(registration)) {
      send(response, 400, { error: 'INVALID_REGISTRATION_RESPONSE' });
      return;
    }
    const challenge = challengeFromClientData(
      registration.response.clientDataJSON, 'webauthn.create',
    );
    if (!challenge) {
      send(response, 400, { error: 'INVALID_REGISTRATION_RESPONSE' });
      return;
    }

    const consumed = await consumeChallenge(supabase, login.userId, challenge, 'registration');
    if (consumed === 'unavailable') {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }
    if (consumed !== 'consumed') {
      send(response, 400, { error: 'CHALLENGE_INVALID' });
      return;
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: registration,
        expectedChallenge: challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        requireUserVerification: true,
      });
    } catch {
      send(response, 400, { error: 'REGISTRATION_VERIFICATION_FAILED' });
      return;
    }
    if (!verification.verified || !verification.registrationInfo) {
      send(response, 400, { error: 'REGISTRATION_VERIFICATION_FAILED' });
      return;
    }

    const { credential } = verification.registrationInfo;
    // 승인 상태·승인자·승인 시각은 클라이언트도, 이 코드도 정하지 않는다.
    // 등록은 항상 pending이며 승인은 Supabase 대시보드에서 사람이 한다.
    const { error } = await supabase.from('device_credentials').insert({
      user_id: login.userId,
      credential_id: credential.id,
      public_key: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: transportsOf(credential.transports ?? registration.response.transports),
      device_name: cleanDeviceName(body.deviceName),
      status: 'pending',
    });
    if (error) {
      send(response, error.code === '23505' ? 409 : 500, {
        error: error.code === '23505' ? 'DEVICE_ALREADY_REGISTERED' : 'DEVICE_REGISTRATION_FAILED',
      });
      return;
    }
    send(response, 201, { status: 'pending' });
  }

  async function authOptions(request, response) {
    const context = await guard(request, response);
    if (!context) return;
    const { login, supabase } = context;

    const { data, error } = await supabase
      .from('device_credentials')
      .select('credential_id, transports, status, approved_by, approved_at')
      .eq('user_id', login.userId)
      .eq('status', 'approved')
      .not('approved_by', 'is', null)
      .not('approved_at', 'is', null);
    if (error || !Array.isArray(data)) {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }
    // 응답 행도 다시 확인해, 필터가 지켜지지 않아도 미승인 자격 증명은 걸러진다.
    const approved = data.filter(isApprovedCredential);
    if (approved.length === 0) {
      send(response, 403, { error: 'NO_APPROVED_DEVICE' });
      return;
    }

    const options = await generateAuthenticationOptions({
      rpID: rp.rpID,
      userVerification: 'required',
      allowCredentials: approved.map(row => ({
        id: row.credential_id, transports: transportsOf(row.transports),
      })),
    });

    if (!await storeChallenge(supabase, login.userId, options.challenge, 'authentication')) {
      send(response, 500, { error: 'DEVICE_CHALLENGE_STORE_FAILED' });
      return;
    }
    send(response, 200, options);
  }

  async function authVerify(request, response) {
    const context = await guard(request, response);
    if (!context) return;
    const { login, supabase } = context;

    const assertion = request.body?.response;
    if (!authenticationShape(assertion)) {
      send(response, 400, { error: 'INVALID_AUTHENTICATION_RESPONSE' });
      return;
    }
    const challenge = challengeFromClientData(
      assertion.response.clientDataJSON, 'webauthn.get',
    );
    if (!challenge) {
      send(response, 400, { error: 'INVALID_AUTHENTICATION_RESPONSE' });
      return;
    }

    // 이 사용자 소유이고 승인 상태인 자격 증명만 대상이다. 챌린지를 쓰기 전에 확인한다.
    const found = await supabase
      .from('device_credentials')
      .select('credential_id, public_key, counter, transports, status, approved_by, approved_at')
      .eq('credential_id', assertion.id)
      .eq('user_id', login.userId)
      .eq('status', 'approved')
      .not('approved_by', 'is', null)
      .not('approved_at', 'is', null)
      .maybeSingle();
    if (found.error) {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }
    const stored = found.data;
    if (!isApprovedCredential(stored)
        || typeof stored.public_key !== 'string'
        || !Number.isSafeInteger(stored.counter) || stored.counter < 0) {
      send(response, 403, { error: 'DEVICE_NOT_APPROVED' });
      return;
    }

    const consumed = await consumeChallenge(supabase, login.userId, challenge, 'authentication');
    if (consumed === 'unavailable') {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }
    if (consumed !== 'consumed') {
      send(response, 400, { error: 'CHALLENGE_INVALID' });
      return;
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertion,
        expectedChallenge: challenge,
        expectedOrigin: rp.origin,
        expectedRPID: rp.rpID,
        requireUserVerification: true,
        credential: {
          id: stored.credential_id,
          publicKey: isoBase64URL.toBuffer(stored.public_key),
          counter: stored.counter,
          transports: transportsOf(stored.transports),
        },
      });
    } catch {
      send(response, 400, { error: 'AUTHENTICATION_VERIFICATION_FAILED' });
      return;
    }
    if (!verification.verified) {
      send(response, 400, { error: 'AUTHENTICATION_VERIFICATION_FAILED' });
      return;
    }

    // 카운터는 "읽은 값이 그대로일 때만, 아직 승인 상태일 때만" 갱신한다(비교 후 교환).
    // 같은 자격 증명으로 동시에 들어온 다른 요청이 먼저 갱신했거나 승인이 해제됐다면 실패한다.
    const updated = await supabase
      .from('device_credentials')
      .update({ counter: verification.authenticationInfo.newCounter, updated_at: now().toISOString() })
      .eq('credential_id', stored.credential_id)
      .eq('user_id', login.userId)
      .eq('status', 'approved')
      .not('approved_by', 'is', null)
      .not('approved_at', 'is', null)
      .eq('counter', stored.counter)
      .select('credential_id');
    if (updated.error) {
      send(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
      return;
    }
    if (!Array.isArray(updated.data) || updated.data.length !== 1) {
      send(response, 409, { error: 'DEVICE_AUTH_CONFLICT' });
      return;
    }

    const session = await issueDeviceSession({
      supabase, userId: login.userId, credentialId: stored.credential_id, now: now(),
    });
    // 세션을 DB에 저장하지 못했다면 쿠키를 발급하지 않는다.
    if (!session) {
      send(response, 500, { error: 'DEVICE_SESSION_FAILED' });
      return;
    }

    response.setHeader('Set-Cookie', deviceSessionCookie(session.token, session.maxAgeSeconds));
    send(response, 200, { ok: true, state: 'session_valid' });
  }

  return { status, registerOptions, registerVerify, authOptions, authVerify };
}
