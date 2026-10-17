import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { before, describe, mock, test } from 'node:test';
import { createDeviceHandlers } from '../src/device-handlers.mjs';
import {
  DEVICE_COOKIE,
  issueDeviceSession,
  requireApprovedDevice,
  revokeDeviceSessionFromCookie,
} from '../src/device-session.mjs';
import { FakeAuthenticator } from './helpers/fake-authenticator.mjs';
import { FakeDb } from './helpers/fake-supabase.mjs';

const HOST = 'vault-test.vercel.app';
const ORIGIN = `https://${HOST}`;
const config = { publicAppUrl: `${ORIGIN}/` };

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const ADMIN = '33333333-3333-4333-8333-333333333333';
const NOTE_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOTE_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

const LOGINS = {
  'student-a': { kind: 'student', userId: USER_A },
  'student-b': { kind: 'student', userId: USER_B },
  judge: { kind: 'judge', userId: USER_A, runId: 'run', identity: 'a' },
};

// 서버의 로그인 검증을 대신하는 테스트 대역: "Bearer student-a" 형태만 안다.
async function fakeVerifyLogin(authorization) {
  const name = typeof authorization === 'string' ? authorization.replace('Bearer ', '') : '';
  return LOGINS[name] ?? null;
}

function makeResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
  };
}

function makeRequest({ method = 'POST', as, cookie, body, query, origin = ORIGIN } = {}) {
  return {
    method,
    query: query ?? {},
    body,
    headers: {
      host: HOST,
      ...(origin ? { origin } : {}),
      ...(as ? { authorization: `Bearer ${as}` } : {}),
      ...(cookie ? { cookie } : {}),
    },
  };
}

async function call(handler, options) {
  const response = makeResponse();
  await handler(makeRequest(options), response);
  return response;
}

function setup() {
  const db = new FakeDb();
  const clock = { time: Date.parse('2026-10-17T00:00:00.000Z') };
  const now = () => new Date(clock.time);
  const handlers = createDeviceHandlers({
    verifyLogin: fakeVerifyLogin, getSupabase: () => db.client(), config, now,
  });
  const authenticator = new FakeAuthenticator({ rpID: HOST, origin: ORIGIN });
  return { db, clock, now, handlers, authenticator };
}

async function registerDevice(ctx, as = 'student-a', extraBody = {}) {
  const options = await call(ctx.handlers.registerOptions, { as });
  assert.equal(options.statusCode, 200);
  return call(ctx.handlers.registerVerify, {
    as,
    body: { deviceName: '테스트 기기', response: ctx.authenticator.createResponse(options.body.challenge), ...extraBody },
  });
}

function approve(db, credentialId, patch = {}) {
  const row = db.rows('device_credentials').find(item => item.credential_id === credentialId);
  Object.assign(row, { status: 'approved', approved_by: ADMIN, approved_at: '2026-10-17T00:00:00.000Z', ...patch });
}

async function loginWithApprovedDevice(ctx, as = 'student-a') {
  await registerDevice(ctx, as);
  approve(ctx.db, ctx.authenticator.id);
  const options = await call(ctx.handlers.authOptions, { as });
  return call(ctx.handlers.authVerify, {
    as, body: { response: ctx.authenticator.getResponse(options.body.challenge) },
  });
}

const sessionCookie = response => String(response.headers['set-cookie']).split(';')[0];

describe('기기 API 입구', () => {
  const routes = ['status', 'registerOptions', 'registerVerify', 'authOptions', 'authVerify'];

  test('로그인하지 않았거나 judge 토큰이면 다섯 API 모두 거부하고 DB를 건드리지 않는다', async () => {
    const ctx = setup();
    for (const route of routes) {
      const anonymous = await call(ctx.handlers[route], { body: {} });
      assert.equal(anonymous.statusCode, 401, `${route} 비로그인`);
      const judge = await call(ctx.handlers[route], { as: 'judge', body: {} });
      assert.equal(judge.statusCode, 403, `${route} judge`);
      assert.equal(judge.body.error, 'STUDENT_ACCOUNT_REQUIRED');
      assert.equal(judge.headers['cache-control'], 'no-store');
    }
    assert.equal(ctx.db.calls.length, 0);
  });

  test('다른 출처와 POST 이외의 메서드는 거부한다', async () => {
    const ctx = setup();
    const crossOrigin = await call(ctx.handlers.status, { as: 'student-a', origin: 'https://evil.example.com' });
    assert.equal(crossOrigin.statusCode, 403);
    const noOrigin = await call(ctx.handlers.status, { as: 'student-a', origin: null });
    assert.equal(noOrigin.statusCode, 403);
    const get = await call(ctx.handlers.status, { method: 'GET', as: 'student-a' });
    assert.equal(get.statusCode, 405);
    assert.equal(ctx.db.calls.length, 0);
  });
});

describe('등록', () => {
  test('등록에 성공해도 자격 증명은 pending이며 승인 정보가 없다', async () => {
    const ctx = setup();
    // 브라우저가 approved 값을 보내도 무시해야 한다.
    const result = await registerDevice(ctx, 'student-a', {
      approved: true, deviceRegistered: true, status: 'approved',
    });
    assert.equal(result.statusCode, 201);
    assert.deepEqual(result.body, { status: 'pending' });

    const [row] = ctx.db.rows('device_credentials');
    assert.equal(row.status, 'pending');
    assert.equal(row.approved_by, null);
    assert.equal(row.approved_at, null);
    assert.equal(row.user_id, USER_A);
    assert.equal(row.credential_id, ctx.authenticator.id);
    assert.equal(typeof row.public_key, 'string');
    assert.deepEqual(row.transports, ['internal']);
    assert.equal(ctx.db.rows('device_sessions').length, 0);

    const status = await call(ctx.handlers.status, { as: 'student-a' });
    assert.equal(status.body.state, 'pending');
    assert.equal(status.body.memoAccess, false);
  });

  test('등록 챌린지는 5분 동안만 유효하고 registration 용도로 저장된다', async () => {
    const ctx = setup();
    const options = await call(ctx.handlers.registerOptions, { as: 'student-a' });
    const [stored] = ctx.db.rows('device_challenges');
    assert.equal(stored.purpose, 'registration');
    assert.equal(stored.user_id, USER_A);
    assert.equal(stored.challenge, options.body.challenge);
    assert.equal(Date.parse(stored.expires_at) - ctx.clock.time, 5 * 60 * 1000);

    ctx.clock.time += 5 * 60 * 1000 + 1000;
    const late = await call(ctx.handlers.registerVerify, {
      as: 'student-a', body: { response: ctx.authenticator.createResponse(options.body.challenge) },
    });
    assert.equal(late.statusCode, 400);
    assert.equal(late.body.error, 'CHALLENGE_INVALID');
    assert.equal(ctx.db.rows('device_credentials').length, 0);
  });

  test('이미 소비된 챌린지, 다른 사용자의 챌린지, 다른 용도의 챌린지는 거부한다', async () => {
    const ctx = setup();
    const options = await call(ctx.handlers.registerOptions, { as: 'student-a' });
    const response = ctx.authenticator.createResponse(options.body.challenge);

    const other = await call(ctx.handlers.registerVerify, { as: 'student-b', body: { response } });
    assert.equal(other.body.error, 'CHALLENGE_INVALID');
    assert.equal(ctx.db.rows('device_credentials').length, 0);

    const first = await call(ctx.handlers.registerVerify, { as: 'student-a', body: { response } });
    assert.equal(first.statusCode, 201);
    const replay = await call(ctx.handlers.registerVerify, { as: 'student-a', body: { response } });
    assert.equal(replay.statusCode, 400);
    assert.equal(replay.body.error, 'CHALLENGE_INVALID');
    assert.equal(ctx.db.rows('device_credentials').length, 1);

    // authentication 용도의 챌린지로 등록할 수 없다.
    ctx.db.rows('device_challenges').push({
      user_id: USER_A, challenge: 'wrong-purpose-challenge-0001', purpose: 'authentication',
      expires_at: new Date(ctx.clock.time + 60000).toISOString(), consumed_at: null,
    });
    const otherAuthenticator = new FakeAuthenticator({ rpID: HOST, origin: ORIGIN });
    const wrongPurpose = await call(ctx.handlers.registerVerify, {
      as: 'student-a',
      body: { response: otherAuthenticator.createResponse('wrong-purpose-challenge-0001') },
    });
    assert.equal(wrongPurpose.body.error, 'CHALLENGE_INVALID');
    assert.equal(ctx.db.rows('device_credentials').length, 1);
  });

  test('다른 출처를 가리키는 등록 응답은 pending 행도 만들지 않는다', async () => {
    const ctx = setup();
    const options = await call(ctx.handlers.registerOptions, { as: 'student-a' });
    const evil = new FakeAuthenticator({ rpID: HOST, origin: 'https://evil.example.com' });
    const result = await call(ctx.handlers.registerVerify, {
      as: 'student-a', body: { response: evil.createResponse(options.body.challenge) },
    });
    assert.equal(result.statusCode, 400);
    assert.equal(result.body.error, 'REGISTRATION_VERIFICATION_FAILED');
    assert.equal(ctx.db.rows('device_credentials').length, 0);
  });

  test('사용자 확인(UV) 없이 만든 등록 응답은 거부한다', async () => {
    const ctx = setup();
    const options = await call(ctx.handlers.registerOptions, { as: 'student-a' });
    const result = await call(ctx.handlers.registerVerify, {
      as: 'student-a',
      body: { response: ctx.authenticator.createResponse(options.body.challenge, { userVerified: false }) },
    });
    assert.equal(result.statusCode, 400);
    assert.equal(ctx.db.rows('device_credentials').length, 0);
  });
});

describe('인증과 기기 세션 발급', () => {
  test('승인된 자격 증명으로 검증에 성공하면 세션이 발급되고 DB에는 해시만 저장된다', async () => {
    const ctx = setup();
    const result = await loginWithApprovedDevice(ctx);
    assert.equal(result.statusCode, 200);
    assert.equal(result.body.state, 'session_valid');

    const cookie = String(result.headers['set-cookie']);
    assert.match(cookie, new RegExp(`^${DEVICE_COOKIE}=[A-Za-z0-9_-]{43};`, 'u'));
    for (const attribute of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict']) {
      assert.ok(cookie.includes(attribute), attribute);
    }
    assert.ok(!cookie.includes('Domain'));

    const token = cookie.split(';')[0].split('=')[1];
    const [session] = ctx.db.rows('device_sessions');
    assert.equal(session.user_id, USER_A);
    assert.equal(session.credential_id, ctx.authenticator.id);
    assert.equal(session.token_hash, createHash('sha256').update(token).digest('hex'));
    assert.notEqual(session.token_hash, token);
    assert.ok(JSON.stringify(ctx.db.rows('device_sessions')).indexOf(token) === -1);
    assert.equal(Date.parse(session.expires_at) > ctx.clock.time, true);

    const [credential] = ctx.db.rows('device_credentials');
    assert.equal(credential.counter, 1);

    const status = await call(ctx.handlers.status, { as: 'student-a', cookie: sessionCookie(result) });
    assert.equal(status.body.state, 'session_valid');
    assert.equal(status.body.memoAccess, true);
    assert.ok(!JSON.stringify(status.body).includes('public_key'));
  });

  for (const status of ['pending', 'rejected', 'revoked']) {
    test(`${status} 자격 증명은 인증 옵션도 세션도 받을 수 없다`, async () => {
      const ctx = setup();
      await registerDevice(ctx);
      Object.assign(ctx.db.rows('device_credentials')[0], { status });

      const options = await call(ctx.handlers.authOptions, { as: 'student-a' });
      assert.equal(options.statusCode, 403);
      assert.equal(options.body.error, 'NO_APPROVED_DEVICE');

      // 서버가 챌린지를 내주지 않더라도, 유효한 서명과 챌린지를 직접 만들어 시도한다.
      ctx.db.rows('device_challenges').push({
        user_id: USER_A, challenge: `forced-auth-challenge-${status}`, purpose: 'authentication',
        expires_at: new Date(ctx.clock.time + 60000).toISOString(), consumed_at: null,
      });
      const forced = await call(ctx.handlers.authVerify, {
        as: 'student-a',
        body: { response: ctx.authenticator.getResponse(`forced-auth-challenge-${status}`) },
      });
      assert.equal(forced.statusCode, 403);
      assert.equal(forced.body.error, 'DEVICE_NOT_APPROVED');
      assert.equal(forced.headers['set-cookie'], undefined);
      assert.equal(ctx.db.rows('device_sessions').length, 0);
    });
  }

  test('status가 approved여도 승인자 또는 승인 시각이 없으면 승인으로 보지 않는다', async () => {
    for (const patch of [{ approved_by: null }, { approved_at: null }]) {
      const ctx = setup();
      await registerDevice(ctx);
      approve(ctx.db, ctx.authenticator.id, patch);
      const options = await call(ctx.handlers.authOptions, { as: 'student-a' });
      assert.equal(options.statusCode, 403);
      const status = await call(ctx.handlers.status, { as: 'student-a' });
      assert.equal(status.body.canAuthenticate, false);
      assert.equal(status.body.memoAccess, false);
    }
  });

  test('다른 사용자의 승인된 자격 증명으로는 인증할 수 없다', async () => {
    const ctx = setup();
    await registerDevice(ctx, 'student-a');
    approve(ctx.db, ctx.authenticator.id);
    // student-b가 student-a의 자격 증명으로 인증을 시도한다.
    ctx.db.rows('device_challenges').push({
      user_id: USER_B, challenge: 'student-b-auth-challenge-1', purpose: 'authentication',
      expires_at: new Date(ctx.clock.time + 60000).toISOString(), consumed_at: null,
    });
    const result = await call(ctx.handlers.authVerify, {
      as: 'student-b',
      body: { response: ctx.authenticator.getResponse('student-b-auth-challenge-1') },
    });
    assert.equal(result.statusCode, 403);
    assert.equal(ctx.db.rows('device_sessions').length, 0);
  });

  test('잘못된 서명·형식의 인증 응답은 세션을 발급하지 않는다', async () => {
    const ctx = setup();
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);

    const attacker = new FakeAuthenticator({ rpID: HOST, origin: ORIGIN });
    const options = await call(ctx.handlers.authOptions, { as: 'student-a' });
    const forged = await call(ctx.handlers.authVerify, {
      as: 'student-a',
      body: { response: { ...ctx.authenticator.getResponse(options.body.challenge, { signWith: attacker.privateKey }) } },
    });
    assert.equal(forged.statusCode, 400);
    assert.equal(forged.body.error, 'AUTHENTICATION_VERIFICATION_FAILED');
    assert.equal(forged.headers['set-cookie'], undefined);

    const malformed = await call(ctx.handlers.authVerify, {
      as: 'student-a', body: { response: { id: ctx.authenticator.id, type: 'public-key' } },
    });
    assert.equal(malformed.statusCode, 400);
    const empty = await call(ctx.handlers.authVerify, { as: 'student-a', body: {} });
    assert.equal(empty.statusCode, 400);

    assert.equal(ctx.db.rows('device_sessions').length, 0);
    assert.equal(ctx.db.rows('device_credentials')[0].counter, 0);
  });

  test('사용자 확인(UV)이 없는 인증 응답과 다른 출처의 인증 응답은 거부한다', async () => {
    const ctx = setup();
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);

    const options = await call(ctx.handlers.authOptions, { as: 'student-a' });
    const noUv = await call(ctx.handlers.authVerify, {
      as: 'student-a',
      body: { response: ctx.authenticator.getResponse(options.body.challenge, { userVerified: false }) },
    });
    assert.equal(noUv.statusCode, 400);

    const second = await call(ctx.handlers.authOptions, { as: 'student-a' });
    ctx.authenticator.origin = 'https://evil.example.com';
    const wrongOrigin = await call(ctx.handlers.authVerify, {
      as: 'student-a', body: { response: ctx.authenticator.getResponse(second.body.challenge) },
    });
    assert.equal(wrongOrigin.statusCode, 400);
    assert.equal(ctx.db.rows('device_sessions').length, 0);
  });

  test('만료되었거나 이미 소비된 인증 챌린지는 거부한다', async () => {
    const ctx = setup();
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);

    const expired = await call(ctx.handlers.authOptions, { as: 'student-a' });
    ctx.clock.time += 5 * 60 * 1000 + 1000;
    const late = await call(ctx.handlers.authVerify, {
      as: 'student-a', body: { response: ctx.authenticator.getResponse(expired.body.challenge) },
    });
    assert.equal(late.statusCode, 400);
    assert.equal(late.body.error, 'CHALLENGE_INVALID');

    const fresh = await call(ctx.handlers.authOptions, { as: 'student-a' });
    const response = ctx.authenticator.getResponse(fresh.body.challenge);
    const first = await call(ctx.handlers.authVerify, { as: 'student-a', body: { response } });
    assert.equal(first.statusCode, 200);
    const replay = await call(ctx.handlers.authVerify, { as: 'student-a', body: { response } });
    assert.equal(replay.statusCode, 400);
    assert.equal(replay.body.error, 'CHALLENGE_INVALID');
    assert.equal(ctx.db.rows('device_sessions').length, 1);
  });

  test('같은 응답을 동시에 두 번 보내도 세션은 한 개만 발급된다', async () => {
    const ctx = setup();
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);
    const options = await call(ctx.handlers.authOptions, { as: 'student-a' });
    const response = ctx.authenticator.getResponse(options.body.challenge);

    const results = await Promise.all([
      call(ctx.handlers.authVerify, { as: 'student-a', body: { response } }),
      call(ctx.handlers.authVerify, { as: 'student-a', body: { response } }),
    ]);
    assert.deepEqual(results.map(item => item.statusCode).sort(), [200, 400]);
    assert.equal(ctx.db.rows('device_sessions').length, 1);
  });

  test('세션 저장에 실패하면 쿠키를 발급하지 않는다', async () => {
    const ctx = setup();
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);
    const options = await call(ctx.handlers.authOptions, { as: 'student-a' });
    ctx.db.failures.add('device_sessions:insert');
    const result = await call(ctx.handlers.authVerify, {
      as: 'student-a', body: { response: ctx.authenticator.getResponse(options.body.challenge) },
    });
    assert.equal(result.statusCode, 500);
    assert.equal(result.headers['set-cookie'], undefined);
    assert.equal(ctx.db.rows('device_sessions').length, 0);
  });

  test('DB 조회 오류가 나면 status도 메모 접근을 열지 않는다', async () => {
    const ctx = setup();
    const issued = await loginWithApprovedDevice(ctx);
    ctx.db.failures.add('device_sessions:select');
    const status = await call(ctx.handlers.status, { as: 'student-a', cookie: sessionCookie(issued) });
    assert.equal(status.statusCode, 503);
    assert.notEqual(status.body.memoAccess, true);
  });
});

describe('requireApprovedDevice (메모 API 공통 검증)', () => {
  async function fixture() {
    const ctx = setup();
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);
    const supabase = ctx.db.client();
    const issued = await issueDeviceSession({
      supabase, userId: USER_A, credentialId: ctx.authenticator.id, now: ctx.now(),
    });
    const cookieHeader = `${DEVICE_COOKIE}=${issued.token}`;
    const check = (login = LOGINS['student-a'], header = cookieHeader) => requireApprovedDevice({
      supabase, login, cookieHeader: header, now: ctx.now(),
    });
    return { ...ctx, supabase, issued, cookieHeader, check };
  }

  test('유효한 세션은 통과한다', async () => {
    const { check, authenticator } = await fixture();
    const result = await check();
    assert.equal(result.ok, true);
    assert.equal(result.credentialId, authenticator.id);
  });

  test('쿠키가 없거나 형식이 틀리거나 모르는 토큰이면 거부한다', async () => {
    const { check } = await fixture();
    // undefined는 check()의 기본값(유효한 쿠키)을 쓰게 되므로 null로 "쿠키 없음"을 표현한다.
    for (const header of [null, '', 'other=1', `${DEVICE_COOKIE}=short`, `${DEVICE_COOKIE}=${'a'.repeat(43)}`]) {
      assert.equal((await check(LOGINS['student-a'], header)).ok, false);
    }
  });

  test('judge 로그인은 거부한다', async () => {
    const { check } = await fixture();
    const result = await check(LOGINS.judge);
    assert.equal(result.ok, false);
    assert.equal(result.status, 403);
  });

  test('만료된 세션은 거부한다', async () => {
    const { check, clock } = await fixture();
    clock.time += 8 * 60 * 60 * 1000 + 1000;
    assert.equal((await check()).ok, false);
  });

  test('회수된 세션은 거부한다', async () => {
    const { check, db, now, cookieHeader, supabase } = await fixture();
    assert.equal(await revokeDeviceSessionFromCookie({ supabase, cookieHeader, now: now() }), 'revoked');
    assert.notEqual(db.rows('device_sessions')[0].revoked_at, null);
    assert.equal((await check()).ok, false);
  });

  test('다른 사용자의 세션 쿠키는 거부한다', async () => {
    const { check } = await fixture();
    assert.equal((await check(LOGINS['student-b'])).ok, false);
  });

  test('자격 증명이 승인에서 pending·rejected·revoked로 바뀌면 기존 세션도 거부한다', async () => {
    for (const status of ['pending', 'rejected', 'revoked']) {
      const { check, db } = await fixture();
      assert.equal((await check()).ok, true);
      db.rows('device_credentials')[0].status = status;
      assert.equal((await check()).ok, false, status);
    }
  });

  test('승인자 또는 승인 시각이 지워지면 기존 세션도 거부한다', async () => {
    for (const field of ['approved_by', 'approved_at']) {
      const { check, db } = await fixture();
      db.rows('device_credentials')[0][field] = null;
      assert.equal((await check()).ok, false, field);
    }
  });

  test('자격 증명의 소유자가 세션 사용자와 다르면 거부한다', async () => {
    const { check, db } = await fixture();
    db.rows('device_credentials')[0].user_id = USER_B;
    assert.equal((await check()).ok, false);
  });

  test('DB 조회 오류나 예외가 나면 기본 거부(503)한다', async () => {
    for (const failure of ['device_sessions:select', 'device_credentials:select']) {
      const { check, db } = await fixture();
      db.failures.add(failure);
      const result = await check();
      assert.equal(result.ok, false, failure);
      assert.equal(result.status, 503);
    }
    const { check, cookieHeader, now } = await fixture();
    const throwing = { from() { throw new Error('boom'); } };
    const result = await requireApprovedDevice({
      supabase: throwing, login: LOGINS['student-a'], cookieHeader, now: now(),
    });
    assert.equal(result.ok, false);
    assert.equal(result.status, 503);
    assert.equal((await check()).ok, true);
  });
});

describe('메모 API에 연결된 기기 검증', () => {
  const state = { db: null };
  let notesList;
  let noteById;
  let logout;

  before(async () => {
    process.env.SUPABASE_URL = 'https://example-project.supabase.co';
    process.env.SUPABASE_SECRET_KEY = 'test-only-not-a-real-key';
    const url = path => new URL(path, import.meta.url).href;

    mock.module('@supabase/supabase-js', {
      namedExports: { createClient: () => state.db.client() },
    });
    mock.module(url('../src/verify-login.mjs'), {
      namedExports: { createLoginVerifier: () => fakeVerifyLogin },
    });

    notesList = (await import(url('../api/notes.js'))).default;
    noteById = (await import(url('../api/notes/[id].js'))).default;
    logout = (await import(url('../api/auth/logout.js'))).default;
  });

  async function notesFixture() {
    const ctx = setup();
    state.db = ctx.db;
    ctx.db.rows('learning_notes').push(
      { id: NOTE_A, owner_id: USER_A, title: 'A의 가상 메모', content: 'A 본문' },
      { id: NOTE_B, owner_id: USER_B, title: 'B의 가상 메모', content: 'B 본문' },
    );
    await registerDevice(ctx);
    approve(ctx.db, ctx.authenticator.id);
    const issued = await issueDeviceSession({
      supabase: ctx.db.client(), userId: USER_A, credentialId: ctx.authenticator.id,
    });
    ctx.db.calls.length = 0;
    return { ...ctx, cookie: `${DEVICE_COOKIE}=${issued.token}` };
  }

  const noteTouches = ctx => ctx.db.callsTo('learning_notes');

  test('승인된 기기 세션이 있으면 본인 메모만 읽는다', async () => {
    const ctx = await notesFixture();
    const result = await call(notesList, { method: 'GET', as: 'student-a', cookie: ctx.cookie });
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.body.map(note => note.id), [NOTE_A]);
  });

  test('기기 세션이 없으면 조회·생성·수정·삭제 모두 거부하고 메모 테이블을 건드리지 않는다', async () => {
    const ctx = await notesFixture();
    const attempts = [
      [notesList, { method: 'GET', as: 'student-a' }],
      [notesList, { method: 'POST', as: 'student-a', body: { title: 't', body: 'b' } }],
      [noteById, { method: 'GET', as: 'student-a', query: { id: NOTE_A } }],
      [noteById, { method: 'PUT', as: 'student-a', query: { id: NOTE_A }, body: { title: '변조', body: '변조' } }],
      [noteById, { method: 'DELETE', as: 'student-a', query: { id: NOTE_A } }],
    ];
    for (const [handler, options] of attempts) {
      const result = await call(handler, options);
      assert.equal(result.statusCode, 403, `${options.method}`);
      assert.equal(result.body.error, 'DEVICE_APPROVAL_REQUIRED');
    }
    assert.equal(noteTouches(ctx).length, 0);
    assert.equal(ctx.db.rows('learning_notes').length, 2);
    assert.equal(ctx.db.rows('learning_notes')[0].title, 'A의 가상 메모');
  });

  test('로그인 세션이 없으면 기기 세션 쿠키만으로는 거부한다', async () => {
    const ctx = await notesFixture();
    const result = await call(notesList, { method: 'GET', cookie: ctx.cookie });
    assert.equal(result.statusCode, 401);
    assert.equal(noteTouches(ctx).length, 0);
  });

  test('만료·회수된 세션과 다른 사용자의 세션은 메모 API에서 거부된다', async () => {
    const expired = await notesFixture();
    expired.db.rows('device_sessions')[0].expires_at = new Date(Date.now() - 1000).toISOString();
    assert.equal((await call(notesList, { method: 'GET', as: 'student-a', cookie: expired.cookie })).statusCode, 403);
    assert.equal(noteTouches(expired).length, 0);

    const revoked = await notesFixture();
    revoked.db.rows('device_sessions')[0].revoked_at = new Date().toISOString();
    assert.equal((await call(notesList, { method: 'GET', as: 'student-a', cookie: revoked.cookie })).statusCode, 403);
    assert.equal(noteTouches(revoked).length, 0);

    const other = await notesFixture();
    assert.equal((await call(notesList, { method: 'GET', as: 'student-b', cookie: other.cookie })).statusCode, 403);
    assert.equal(noteTouches(other).length, 0);
  });

  test('승인 상태가 해제되면 이미 발급된 세션으로도 메모에 접근할 수 없다', async () => {
    for (const status of ['pending', 'rejected', 'revoked']) {
      const ctx = await notesFixture();
      assert.equal((await call(notesList, { method: 'GET', as: 'student-a', cookie: ctx.cookie })).statusCode, 200);
      ctx.db.rows('device_credentials')[0].status = status;
      ctx.db.calls.length = 0;
      const result = await call(notesList, { method: 'GET', as: 'student-a', cookie: ctx.cookie });
      assert.equal(result.statusCode, 403, status);
      assert.equal(noteTouches(ctx).length, 0);
    }
  });

  test('기기 DB 조회 오류가 나면 메모 접근을 허용하지 않는다', async () => {
    for (const failure of ['device_sessions:select', 'device_credentials:select']) {
      const ctx = await notesFixture();
      ctx.db.failures.add(failure);
      const result = await call(notesList, { method: 'GET', as: 'student-a', cookie: ctx.cookie });
      assert.equal(result.statusCode, 503, failure);
      assert.equal(noteTouches(ctx).length, 0);
    }
  });

  test('기기 세션이 유효해도 다른 사용자의 메모는 조회·수정·삭제할 수 없다', async () => {
    const ctx = await notesFixture();
    const read = await call(noteById, { method: 'GET', as: 'student-a', cookie: ctx.cookie, query: { id: NOTE_B } });
    assert.equal(read.statusCode, 404);
    const write = await call(noteById, {
      method: 'PUT', as: 'student-a', cookie: ctx.cookie, query: { id: NOTE_B }, body: { title: '탈취', body: '탈취' },
    });
    assert.equal(write.statusCode, 404);
    const remove = await call(noteById, { method: 'DELETE', as: 'student-a', cookie: ctx.cookie, query: { id: NOTE_B } });
    assert.equal(remove.statusCode, 404);
    const [, noteB] = ctx.db.rows('learning_notes');
    assert.equal(noteB.title, 'B의 가상 메모');
    assert.equal(ctx.db.rows('learning_notes').length, 2);

    const own = await call(noteById, { method: 'GET', as: 'student-a', cookie: ctx.cookie, query: { id: NOTE_A } });
    assert.equal(own.statusCode, 200);
  });

  test('로그아웃하면 두 쿠키를 모두 지우고 현재 기기 세션을 DB에서 회수한다', async () => {
    const ctx = await notesFixture();
    const response = await call(logout, { cookie: `__Host-byte-back-session=a.b.c; ${ctx.cookie}` });
    assert.equal(response.statusCode, 200);

    const cookies = response.headers['set-cookie'];
    assert.equal(Array.isArray(cookies), true);
    assert.ok(cookies.some(item => item.startsWith('__Host-byte-back-session=;') && item.includes('Max-Age=0')));
    assert.ok(cookies.some(item => item.startsWith(`${DEVICE_COOKIE}=;`) && item.includes('Max-Age=0')));
    assert.notEqual(ctx.db.rows('device_sessions')[0].revoked_at, null);

    const afterwards = await call(notesList, { method: 'GET', as: 'student-a', cookie: ctx.cookie });
    assert.equal(afterwards.statusCode, 403);
  });

  test('회수에 실패해도 쿠키는 지우고 실패를 숨기지 않는다', async () => {
    const ctx = await notesFixture();
    ctx.db.failures.add('device_sessions:update');
    const response = await call(logout, { cookie: ctx.cookie });
    assert.equal(response.statusCode, 500);
    assert.equal(response.body.error, 'DEVICE_SESSION_REVOKE_FAILED');
    assert.ok(response.headers['set-cookie'].some(item => item.startsWith(`${DEVICE_COOKIE}=;`)));
  });
});
