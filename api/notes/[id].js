import { createLoginVerifier } from '../../src/verify-login.mjs';
import config from '../../aleph.config.json' with { type: 'json' };
import { createClient } from '@supabase/supabase-js';

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

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

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
    });
    return;
  }

  const login = await verifyLogin(
    request.headers.authorization
  );

  if (!login) {
    response.status(401).json({
      error: 'UNAUTHORIZED',
    });
    return;
  }

  if (!supabaseUrl || !supabaseSecretKey) {
    response.status(500).json({
      error: 'SUPABASE_SERVER_CONFIG_MISSING',
    });
    return;
  }

  const { id } = request.query;

  if (typeof id !== 'string' || !UUID.test(id)) {
    response.status(400).json({
      error: 'INVALID_NOTE_ID',
    });
    return;
  }

  const supabase = getSupabase();

  // 단건 조회
  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('learning_notes')
      .select('id, title, content')
      .eq('id', id)
      .eq('owner_id', login.userId)
      .maybeSingle();

    if (error) {
      response.status(500).json({
        error: 'LEARNING_NOTE_READ_FAILED',
      });
      return;
    }

    if (!data) {
      response.status(404).json({
        error: 'NOTE_NOT_FOUND',
      });
      return;
    }

    response.status(200).json({
      id: data.id,
      title: data.title,
      body: data.content,
    });
    return;
  }

  // 수정
  if (request.method === 'PUT') {
    if (
      !request.body ||
      typeof request.body.title !== 'string' ||
      typeof request.body.body !== 'string'
    ) {
      response.status(400).json({
        error: 'INVALID_NOTE_BODY',
      });
      return;
    }

    const { data, error } = await supabase
      .from('learning_notes')
      .update({
        title: request.body.title,
        content: request.body.body,
      })
      .eq('id', id)
      .eq('owner_id', login.userId)
      .maybeSingle();

    if (error) {
      response.status(500).json({
        error: 'LEARNING_NOTE_UPDATE_FAILED',
      });
      return;
    }

    if (!data) {
      response.status(404).json({
        error: 'NOTE_NOT_FOUND',
      });
      return;
    }

    response.status(200).json({
      id: data.id,
      title: data.title,
      body: data.content,
    });
    return;
  }

  // 삭제
  const { data, error } = await supabase
    .from('learning_notes')
    .delete()
    .eq('id', id)
    .eq('owner_id', login.userId)
    .select('id')
    .maybeSingle();

  if (error) {
    response.status(500).json({
      error: 'LEARNING_NOTE_DELETE_FAILED',
    });
    return;
  }

  if (!data) {
    response.status(404).json({
      error: 'NOTE_NOT_FOUND',
    });
    return;
  }

  response.status(200).json({
    id: data.id,
  });
}