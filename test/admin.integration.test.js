import 'dotenv/config';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, test } from 'node:test';
import bcrypt from 'bcryptjs';

process.env.NODE_ENV = 'test';
process.env.ADMIN_EMAIL = `admin-${randomUUID()}@example.test`;
process.env.ADMIN_SESSION_SECRET = randomUUID() + randomUUID();
process.env.ADMIN_ORIGIN = 'http://localhost:5174';

const { app, connectDatabase } = await import('../src/server.js');
const { default: mongoose } = await import('mongoose');
const { default: Contact } = await import('../src/models/Contact.js');
const testEmail = `visitor-${randomUUID()}@example.test`;
const testPassword = `test-${randomUUID()}-password`;
process.env.ADMIN_PASSWORD_HASH = await bcrypt.hash(testPassword, 4);

let server;
let baseUrl;
let sessionCookies = '';
let csrfToken = '';

function cookieValue(response, name) {
  const cookies = response.headers.getSetCookie?.() ?? [response.headers.get('set-cookie') || ''];
  const match = cookies.map((cookie) => cookie.match(new RegExp(`${name}=([^;,]+)`))).find(Boolean);
  return match?.[1];
}

function withAdmin(options = {}) {
  return {
    ...options,
    headers: {
      Origin: 'http://localhost:5174',
      ...(sessionCookies ? { Cookie: sessionCookies } : {}),
      ...(options.method && options.method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}),
      ...(options.headers || {}),
    },
  };
}

after(async () => {
  await Contact.deleteOne({ email: testEmail }).catch(() => {});
  if (server) await new Promise((resolve) => server.close(resolve));
  await mongoose.disconnect();
});

test('public contact submission and protected admin request workflow', async () => {
  assert.ok(process.env.MONGODB_URI, 'MONGODB_URI must be configured to run the MongoDB integration test');
  await connectDatabase();
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  const deniedResponse = await fetch(`${baseUrl}/api/admin/contacts`);
  assert.equal(deniedResponse.status, 401);
  const deniedStats = await fetch(`${baseUrl}/api/admin/dashboard/stats`);
  assert.equal(deniedStats.status, 401);
  const deniedDetail = await fetch(`${baseUrl}/api/admin/contacts/not-an-id`);
  assert.equal(deniedDetail.status, 401);

  const visitorResponse = await fetch(`${baseUrl}/api/contact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:5173' },
    body: JSON.stringify({
      name: 'Integration Visitor',
      email: testEmail,
      subject: 'Admin dashboard workflow test',
      message: 'This test message should be visible only to an authenticated admin.',
    }),
  });
  assert.equal(visitorResponse.status, 201);

  const csrfResponse = await fetch(`${baseUrl}/api/admin/csrf`, { headers: { Origin: 'http://localhost:5174' } });
  assert.equal(csrfResponse.status, 200);
  csrfToken = (await csrfResponse.json()).csrfToken;
  const csrfCookie = cookieValue(csrfResponse, 'portfolio_admin_csrf');
  assert.ok(csrfCookie);
  sessionCookies = `portfolio_admin_csrf=${csrfCookie}`;

  const invalidLogin = await fetch(`${baseUrl}/api/admin/login`, withAdmin({
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: process.env.ADMIN_EMAIL, password: 'not-the-password' }),
  }));
  assert.equal(invalidLogin.status, 401);

  const loginResponse = await fetch(`${baseUrl}/api/admin/login`, withAdmin({
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: process.env.ADMIN_EMAIL, password: testPassword }),
  }));
  assert.equal(loginResponse.status, 200);
  const sessionCookie = cookieValue(loginResponse, 'portfolio_admin_session');
  assert.ok(sessionCookie);
  sessionCookies += `; portfolio_admin_session=${sessionCookie}`;

  const meResponse = await fetch(`${baseUrl}/api/admin/me`, withAdmin());
  assert.equal(meResponse.status, 200);

  const invalidQuery = await fetch(`${baseUrl}/api/admin/contacts?page=0`, withAdmin());
  assert.equal(invalidQuery.status, 400);
  const invalidId = await fetch(`${baseUrl}/api/admin/contacts/not-an-id`, withAdmin());
  assert.equal(invalidId.status, 400);

  const statsResponse = await fetch(`${baseUrl}/api/admin/dashboard/stats`, withAdmin());
  assert.equal(statsResponse.status, 200);
  const stats = await statsResponse.json();
  assert.ok(stats.total >= 1);

  const listResponse = await fetch(`${baseUrl}/api/admin/contacts?search=${encodeURIComponent(testEmail)}&status=New`, withAdmin());
  assert.equal(listResponse.status, 200);
  const list = await listResponse.json();
  assert.equal(list.pagination.total, 1);
  assert.equal(list.items[0].email, testEmail);
  const id = list.items[0]._id;

  const detailResponse = await fetch(`${baseUrl}/api/admin/contacts/${id}`, withAdmin());
  assert.equal(detailResponse.status, 200);
  const detail = await detailResponse.json();
  assert.match(detail.message, /authenticated admin/);

  const missingCsrf = await fetch(`${baseUrl}/api/admin/contacts/${id}/status`, {
    method: 'PATCH',
    headers: {
      Origin: 'http://localhost:5174',
      Cookie: sessionCookies,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ status: 'Read' }),
  });
  assert.equal(missingCsrf.status, 403);

  const invalidStatus = await fetch(`${baseUrl}/api/admin/contacts/${id}/status`, withAdmin({
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: 'Owner' }),
  }));
  assert.equal(invalidStatus.status, 400);

  const statusResponse = await fetch(`${baseUrl}/api/admin/contacts/${id}/status`, withAdmin({
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: 'Replied' }),
  }));
  assert.equal(statusResponse.status, 200);
  assert.equal((await statusResponse.json()).status, 'Replied');

  const deleteResponse = await fetch(`${baseUrl}/api/admin/contacts/${id}`, withAdmin({ method: 'DELETE' }));
  assert.equal(deleteResponse.status, 204);
  const missingResponse = await fetch(`${baseUrl}/api/admin/contacts/${id}`, withAdmin());
  assert.equal(missingResponse.status, 404);

  const logoutResponse = await fetch(`${baseUrl}/api/admin/logout`, withAdmin({ method: 'POST' }));
  assert.equal(logoutResponse.status, 204);
  sessionCookies = `portfolio_admin_csrf=${csrfCookie}`;
  const afterLogoutResponse = await fetch(`${baseUrl}/api/admin/me`, withAdmin());
  assert.equal(afterLogoutResponse.status, 401);

  for (let attempt = 0; attempt < 6; attempt += 1) {
    const failedLogin = await fetch(`${baseUrl}/api/admin/login`, withAdmin({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: process.env.ADMIN_EMAIL, password: 'incorrect-password' }),
    }));
    assert.equal(failedLogin.status, 401);
  }
  const rateLimitedLogin = await fetch(`${baseUrl}/api/admin/login`, withAdmin({
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: process.env.ADMIN_EMAIL, password: 'incorrect-password' }),
  }));
  assert.equal(rateLimitedLogin.status, 429);
});
