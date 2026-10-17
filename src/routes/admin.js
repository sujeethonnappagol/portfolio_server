import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import Contact from '../models/Contact.js';
import {
  csrfCookieName,
  csrfCookieOptions,
  isAdminAuthConfigured,
  requireAdmin,
  requireCsrf,
  sessionCookieName,
  sessionCookieOptions,
  sessionDurationMs,
} from '../middleware/adminAuth.js';

const router = Router();
const statuses = ['New', 'Read', 'Replied', 'Archived'];
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Please try again in 15 minutes.' },
});

const trustedOrigins = new Set([
  ...(process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(','),
  ...(process.env.ADMIN_ORIGIN || 'http://localhost:5174').split(','),
].map((origin) => origin.trim()).filter(Boolean));

router.use((request, response, next) => {
  if (['POST', 'PATCH', 'DELETE'].includes(request.method)) {
    const origin = request.get('Origin');
    if (origin && !trustedOrigins.has(origin)) {
      return response.status(403).json({ error: 'Request origin is not allowed.' });
    }
  }
  return next();
});

router.get('/csrf', (_request, response) => {
  const csrfToken = randomBytes(32).toString('hex');
  response.cookie(csrfCookieName, csrfToken, csrfCookieOptions());
  return response.json({ csrfToken });
});

router.post('/login', loginLimiter, requireCsrf, async (request, response) => {
  if (!isAdminAuthConfigured()) {
    return response.status(503).json({ error: 'Admin sign-in is not configured on this server.' });
  }

  const { email, password } = request.body ?? {};
  if (typeof email !== 'string' || typeof password !== 'string' || email.length > 254 || password.length > 200) {
    return response.status(400).json({ error: 'Enter a valid email address and password.' });
  }

  let passwordMatches = false;
  try {
    passwordMatches = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  } catch {
    return response.status(503).json({ error: 'Admin sign-in is not configured correctly.' });
  }

  const emailMatches = email.trim().toLowerCase() === process.env.ADMIN_EMAIL.trim().toLowerCase();
  if (!emailMatches || !passwordMatches) {
    return response.status(401).json({ error: 'Email or password is incorrect.' });
  }

  const token = jwt.sign(
    { role: 'admin' },
    process.env.ADMIN_SESSION_SECRET,
    {
      subject: process.env.ADMIN_EMAIL.trim().toLowerCase(),
      expiresIn: Math.floor(sessionDurationMs / 1000),
      issuer: 'sujeet-portfolio-admin',
      audience: 'sujeet-portfolio-admin',
      algorithm: 'HS256',
    },
  );
  response.cookie(sessionCookieName, token, sessionCookieOptions());
  return response.json({ email: process.env.ADMIN_EMAIL.trim().toLowerCase() });
});

router.post('/logout', requireCsrf, (_request, response) => {
  response.clearCookie(sessionCookieName, { ...sessionCookieOptions(), maxAge: undefined });
  response.clearCookie(csrfCookieName, { ...csrfCookieOptions(), maxAge: undefined });
  return response.status(204).end();
});

router.get('/me', requireAdmin, (request, response) => {
  response.json({ email: request.admin.email });
});

router.get('/dashboard/stats', requireAdmin, async (_request, response, next) => {
  try {
    const [result] = await Contact.aggregate([
      { $project: { normalizedStatus: { $ifNull: ['$status', 'New'] } } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          new: { $sum: { $cond: [{ $eq: ['$normalizedStatus', 'New'] }, 1, 0] } },
          read: { $sum: { $cond: [{ $eq: ['$normalizedStatus', 'Read'] }, 1, 0] } },
          replied: { $sum: { $cond: [{ $eq: ['$normalizedStatus', 'Replied'] }, 1, 0] } },
          archived: { $sum: { $cond: [{ $eq: ['$normalizedStatus', 'Archived'] }, 1, 0] } },
        },
      },
      { $project: { _id: 0, total: 1, new: 1, read: 1, replied: 1, archived: 1 } },
    ]);
    return response.json(result || { total: 0, new: 0, read: 0, replied: 0, archived: 0 });
  } catch (error) {
    return next(error);
  }
});

router.get('/contacts', requireAdmin, async (request, response, next) => {
  const page = Number(request.query.page ?? 1);
  const limit = Number(request.query.limit ?? 10);
  const status = request.query.status ?? 'All';
  const sort = request.query.sort ?? 'newest';
  const search = typeof request.query.search === 'string' ? request.query.search.trim() : '';

  if (!Number.isInteger(page) || page < 1 || page > 1000000
    || !Number.isInteger(limit) || limit < 1 || limit > 100
    || !['All', ...statuses].includes(status)
    || !['newest', 'oldest'].includes(sort)
    || search.length > 120) {
    return response.status(400).json({ error: 'Invalid contact list query.' });
  }

  const filters = [];
  if (status !== 'All') {
    filters.push(status === 'New'
      ? { $or: [{ status: 'New' }, { status: { $exists: false } }] }
      : { status });
  }
  if (search) {
    const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const expression = new RegExp(escapedSearch, 'i');
    filters.push({ $or: [{ name: expression }, { email: expression }, { subject: expression }] });
  }
  const filter = filters.length ? { $and: filters } : {};
  const skip = (page - 1) * limit;
  const direction = sort === 'oldest' ? 1 : -1;

  try {
    const [items, total] = await Promise.all([
      Contact.find(filter)
        .select('name email subject status createdAt')
        .sort({ createdAt: direction, _id: direction })
        .skip(skip)
        .limit(limit)
        .lean(),
      Contact.countDocuments(filter),
    ]);
    return response.json({
      items,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/contacts/:id', requireAdmin, async (request, response, next) => {
  if (!mongoose.isObjectIdOrHexString(request.params.id)) {
    return response.status(400).json({ error: 'Invalid contact ID.' });
  }
  try {
    const contact = await Contact.findById(request.params.id).lean();
    if (!contact) return response.status(404).json({ error: 'Contact request not found.' });
    return response.json(contact);
  } catch (error) {
    return next(error);
  }
});

router.patch('/contacts/:id/status', requireAdmin, requireCsrf, async (request, response, next) => {
  if (!mongoose.isObjectIdOrHexString(request.params.id)) {
    return response.status(400).json({ error: 'Invalid contact ID.' });
  }
  const { status } = request.body ?? {};
  if (typeof status !== 'string' || !statuses.includes(status)) {
    return response.status(400).json({ error: 'Choose a valid request status.' });
  }
  try {
    const contact = await Contact.findByIdAndUpdate(
      request.params.id,
      { $set: { status } },
      { new: true, runValidators: true },
    ).lean();
    if (!contact) return response.status(404).json({ error: 'Contact request not found.' });
    return response.json(contact);
  } catch (error) {
    return next(error);
  }
});

router.delete('/contacts/:id', requireAdmin, requireCsrf, async (request, response, next) => {
  if (!mongoose.isObjectIdOrHexString(request.params.id)) {
    return response.status(400).json({ error: 'Invalid contact ID.' });
  }
  try {
    const contact = await Contact.findByIdAndDelete(request.params.id);
    if (!contact) return response.status(404).json({ error: 'Contact request not found.' });
    return response.status(204).end();
  } catch (error) {
    return next(error);
  }
});

export default router;