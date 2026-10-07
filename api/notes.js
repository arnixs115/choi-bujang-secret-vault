import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };
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

  if (!['GET', 'POST'].includes(request.method)) {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const login = await verifyLogin(request.headers.authorization);

  if (!login) {
    response.status(401).json({ error: 'UNAUTHORIZED' });
    return;
  }

  if (!supabaseUrl || !supabaseSecretKey) {
    response.status(500).json({
      error: 'SUPABASE_SERVER_CONFIG_MISSING',
    });
    return;
  }

  const supabase = getSupabase();

  // 목록 조회
  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('learning_notes')
      .select('id, title, content')
      .eq('owner_id', login.userId)
      .order('created_at', { ascending: true });

    if (error) {
      response.status(500).json({
        error: 'LEARNING_NOTES_READ_FAILED',
      });
      return;
    }

    response.status(200).json(
      data.map(note => ({
        id: note.id,
        title: note.title,
        body: note.content,
      }))
    );
    return;
  }

  // 메모 생성
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

  const id =
    request.body.id === undefined
      ? crypto.randomUUID()
      : request.body.id;

  if (typeof id !== 'string' || !UUID.test(id)) {
    response.status(400).json({
      error: 'INVALID_NOTE_ID',
    });
    return;
  }

  const { error } = await supabase
    .from('learning_notes')
    .insert({
      id,
      owner_id: login.userId,
      title: request.body.title,
      content: request.body.body,
    });

  if (error) {
    response.status(
      error.code === '23505' ? 409 : 500
    ).json({
      error:
        error.code === '23505'
          ? 'NOTE_ID_ALREADY_EXISTS'
          : 'LEARNING_NOTE_CREATE_FAILED',
    });
    return;
  }

  response.status(201).json({ id });
}
