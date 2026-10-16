
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    response.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
    });
    return;
  }

  response.setHeader(
    'Set-Cookie',
    '__Host-byte-back-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
  );

  response.status(200).json({
    ok: true,
  });
}
