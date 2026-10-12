
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL;
const supabasePublishableKey =
  process.env.SUPABASE_PUBLISHABLE_KEY;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
    });
    return;
  }

  const { email, password } = request.body ?? {};

  if (
    typeof email !== 'string' ||
    typeof password !== 'string' ||
    !email.trim() ||
    !password
  ) {
    response.status(400).json({
      error: 'INVALID_LOGIN_INPUT',
    });
    return;
  }

  if (!supabaseUrl || !supabasePublishableKey) {
    response.status(500).json({
      error: 'SUPABASE_AUTH_CONFIG_MISSING',
    });
    return;
  }

  const supabase = createClient(
    supabaseUrl,
    supabasePublishableKey,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    }
  );

  const { data, error } =
    await supabase.auth.signInWithPassword({
      email: email.trim(),
      password,
    });

  if (error || !data.session) {
    response.status(401).json({
      error: 'LOGIN_FAILED',
    });
    return;
  }

  response.status(200).json({
    access_token: data.session.access_token,
    expires_at: data.session.expires_at,
    user: {
      id: data.user.id,
      email: data.user.email,
    },
  });
}
