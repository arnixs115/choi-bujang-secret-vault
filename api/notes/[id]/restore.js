
import { createLoginVerifier } from '../../../src/verify-login.mjs';
import { requireApprovedDevice } from '../../../src/device-session.mjs';
import { hasSameOrigin } from '../../../src/verify-origin.mjs';
import config from '../../../aleph.config.json' with { type: 'json' };
import { createClient } from '@supabase/supabase-js';

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

const SHA256 = /^[0-9a-f]{64}$/u;

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

const verifyLogin = createLoginVerifier({
  config,
  supabaseSecretKey,
});

function getSupabase() {
  return createClient(supabaseUrl, supabaseSecretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  if (
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) &&
    !hasSameOrigin(request)
  ) {
    response.status(403).json({
      error: 'INVALID_ORIGIN',
    });
    return;
  }

  const login = await verifyLogin(request.headers.authorization, request.headers.cookie);

  if (!login) {
    response.status(401).json({ error: 'UNAUTHORIZED' });
    return;
  }

  // 실제 학생 계정만 허용한다.
  if (login.kind !== 'student') {
    response.status(403).json({ error: 'STUDENT_ACCOUNT_REQUIRED' });
    return;
  }

  if (!supabaseUrl || !supabaseSecretKey) {
    response.status(500).json({
      error: 'SUPABASE_SERVER_CONFIG_MISSING',
    });
    return;
  }

  const supabase = getSupabase();

  // 복원도 메모를 바꾸는 작업이므로 같은 기기 세션 검사를 먼저 통과해야 한다.
  const device = await requireApprovedDevice({
    supabase,
    login,
    cookieHeader: request.headers.cookie,
  });

  if (!device.ok) {
    response.status(device.status).json({ error: device.error });
    return;
  }

  const { id } = request.query;

  if (typeof id !== 'string' || !UUID.test(id)) {
    response.status(400).json({ error: 'INVALID_NOTE_ID' });
    return;
  }

  const { snapshotId, contentSha256 } = request.body ?? {};

  if (
    typeof snapshotId !== 'string' ||
    !UUID.test(snapshotId) ||
    typeof contentSha256 !== 'string' ||
    !SHA256.test(contentSha256)
  ) {
    response.status(400).json({
      error: 'INVALID_RESTORE_INPUT',
    });
    return;
  }

  const { data, error } = await supabase.rpc(
    'restore_learning_note_snapshot',
    {
      p_note_id: id,
      p_snapshot_id: snapshotId,
      p_owner_id: login.userId,
      p_expected_sha256: contentSha256,
    }
  );

  if (error) {
    if (error.code === 'P0002') {
      response.status(404).json({
        error: 'SNAPSHOT_OR_NOTE_NOT_FOUND',
      });
      return;
    }

    if (error.code === '22000') {
      response.status(409).json({
        error: 'SNAPSHOT_HASH_MISMATCH',
      });
      return;
    }

    if (error.code === '22023') {
      response.status(400).json({
        error: 'INVALID_RESTORE_INPUT',
      });
      return;
    }

    response.status(500).json({
      error: 'NOTE_RESTORE_FAILED',
    });
    return;
  }

  const restored = Array.isArray(data) ? data[0] : data;

  if (
    !restored ||
    restored.note_id !== id ||
    restored.owner_id !== login.userId ||
    restored.content_sha256 !== contentSha256 ||
    typeof restored.audit_id !== 'string'
  ) {
    response.status(500).json({
      error: 'RESTORE_RESULT_VALIDATION_FAILED',
    });
    return;
  }

  response.status(200).json({
    id: restored.note_id,
    ownerId: restored.owner_id,
    contentSha256: restored.content_sha256,
    auditId: restored.audit_id,
  });
}