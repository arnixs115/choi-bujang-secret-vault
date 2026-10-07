import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

const verifyLogin = createLoginVerifier({
  config,
  supabaseSecretKey,
});

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const authorization = request.headers.authorization;
  const login = await verifyLogin(authorization);

  if (!login) {
    response.status(401).json({ error: 'UNAUTHORIZED' });
    return;
  }

  if (!supabaseUrl || !supabaseSecretKey) {
    response.status(500).json({ error: 'SUPABASE_SERVER_CONFIG_MISSING' });
    return;
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const { data, error } = await supabase
    .from('learning_notes')
    .select('id, title, content')
    .order('id', { ascending: true });

  if (error) {
    response.status(500).json({ error: 'LEARNING_NOTES_READ_FAILED' });
    return;
  }

  response.status(200).json({ notes: data });
}
