export function hasSameOrigin(request) {
  const origin = request.headers.origin;
  const host = request.headers.host;

  if (
    typeof origin !== 'string' ||
    typeof host !== 'string' ||
    !host
  ) {
    return false;
  }

  try {
    const parsedOrigin = new URL(origin);
    const forwardedProto = request.headers['x-forwarded-proto'];
    const protocol = typeof forwardedProto === 'string'
      ? forwardedProto.split(',')[0].trim()
      : host.startsWith('localhost:') ||
          host.startsWith('127.0.0.1:')
        ? 'http'
        : 'https';

    return (
      parsedOrigin.host === host &&
      parsedOrigin.protocol === `${protocol}:` &&
      ['https:', 'http:'].includes(parsedOrigin.protocol) &&
      (parsedOrigin.protocol !== 'http:' ||
        host.startsWith('localhost:') ||
        host.startsWith('127.0.0.1:'))
    );
  } catch {
    return false;
  }
}
