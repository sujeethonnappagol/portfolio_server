import { timingSafeEqual } from 'node:crypto';
import jwt from 'jsonwebtoken';

export const sessionCookieName = 'portfolio_admin_session';
export const csrfCookieName = 'portfolio_admin_csrf';
export const sessionDurationMs = 15 * 60 * 1000;

export function sessionCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/admin',
    maxAge: sessionDurationMs,
  };
}

export function csrfCookieOptions() {
  return {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/admin',
    maxAge: sessionDurationMs,
  };
}

export function isAdminAuthConfigured() {
  return Boolean(
    process.env.ADMIN_EMAIL
    && /^\$2[aby]\$/.test(process.env.ADMIN_PASSWORD_HASH || '')
    && Buffer.byteLength(process.env.ADMIN_SESSION_SECRET || '', 'utf8') >= 32,
  );
}

export function requireAdmin(request, response, next) {
  const token = request.cookies?.[sessionCookieName];
  if (!token || !isAdminAuthConfigured()) {
    return response.status(401).json({ error: 'Authentication required.' });
  }

  try {
    const session = jwt.verify(token, process.env.ADMIN_SESSION_SECRET, {
      algorithms: ['HS256'],
      issuer: 'sujeet-portfolio-admin',
      audience: 'sujeet-portfolio-admin',
    });
    if (session.role !== 'admin' || session.sub !== process.env.ADMIN_EMAIL.trim().toLowerCase()) {
      return response.status(401).json({ error: 'Authentication required.' });
    }
    request.admin = { email: session.sub };
    return next();
  } catch {
    return response.status(401).json({ error: 'Authentication required.' });
  }
}

export function requireCsrf(request, response, next) {
  const cookieToken = request.cookies?.[csrfCookieName];
  const headerToken = request.get('X-CSRF-Token');
  if (!cookieToken || !headerToken || cookieToken.length !== headerToken.length) {
    return response.status(403).json({ error: 'Security token missing or invalid. Refresh and try again.' });
  }

  const cookieBuffer = Buffer.from(cookieToken);
  const headerBuffer = Buffer.from(headerToken);
  if (!cookieBuffer.length || cookieBuffer.length !== headerBuffer.length || !timingSafeEqual(cookieBuffer, headerBuffer)) {
    return response.status(403).json({ error: 'Security token missing or invalid. Refresh and try again.' });
  }
  return next();
}