// Minimal replacement for Supabase Auth, built against a real pg_dumpall
// restore of the paused Supabase project. Scope is intentionally narrow:
// login + TOTP MFA only, matching what home.html's doLogin()/verifyLogin2fa()
// actually need. Everything else the dashboard does (tickets, chats,
// invoices, etc.) still depends on the Supabase JS client directly and is
// NOT covered here yet — that's the larger migration, scoped down for this
// weekend to just the login path per the plan agreed with the founder.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const fs = require('fs');
const path = require('path');
const { pool } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set — refusing to start.');
  process.exit(1);
}
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://auth.supanta.com';

function issueSession(authUser, profile) {
  const payload = {
    sub: authUser.id,
    email: authUser.email,
    // Literally the Postgres role PostgREST should switch into for this
    // request (it reads the JWT's "role" claim for that) — NOT the app-level
    // role (admin/super_admin/etc). That lives in user_profiles and is what
    // RLS policies like is_admin()/has_client_access() look up via auth.uid(),
    // and is what /auth/session returns separately for the UI to use.
    role: 'authenticated',
    app_role: profile ? profile.role : null,
    client_id: profile ? profile.client_id : null,
    full_name: profile ? profile.full_name : null,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  return { token, user: payload };
}

async function getProfile(userId) {
  const { rows } = await pool.query(
    `select p.id, p.full_name, p.email, p.role, p.client_id, p.job_title, p.links, p.cookie_consent,
            c.company_name, c.account_type
     from public.user_profiles p
     left join public.clients c on c.id = p.client_id
     where p.id = $1`,
    [userId]
  );
  return rows[0] || null;
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Mirrors supabase-js's auth.signInWithPassword(): verify credentials, and
// if the account has a verified TOTP factor, stop short of issuing a
// session (home.html expects this — it shows the 2FA step instead of
// redirecting straight into the dashboard).
app.post('/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

    const { rows } = await pool.query(
      'select id, email, encrypted_password from auth.users where lower(email) = $1 and deleted_at is null',
      [email]
    );
    const authUser = rows[0];
    // Same generic message whether the email doesn't exist or the password
    // is wrong — don't let a 401 reveal which one.
    const genericError = () => res.status(401).json({ error: 'Invalid email or password' });
    if (!authUser || !authUser.encrypted_password) return genericError();

    const ok = await bcrypt.compare(password, authUser.encrypted_password);
    if (!ok) return genericError();

    const { rows: factorRows } = await pool.query(
      "select id from auth.mfa_factors where user_id = $1 and factor_type = 'totp' and status = 'verified' limit 1",
      [authUser.id]
    );
    if (factorRows[0]) {
      return res.json({ mfa_required: true, factor_id: factorRows[0].id });
    }

    const profile = await getProfile(authUser.id);
    return res.json(issueSession(authUser, profile));
  } catch (e) {
    console.error('login error', e);
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

app.post('/auth/mfa/verify', async (req, res) => {
  try {
    const factorId = String(req.body.factor_id || '');
    const code = String(req.body.code || '').trim();
    if (!factorId || !code) return res.status(400).json({ error: 'Missing factor_id or code' });

    const { rows } = await pool.query(
      "select user_id, secret from auth.mfa_factors where id = $1 and factor_type = 'totp' and status = 'verified'",
      [factorId]
    );
    const factor = rows[0];
    if (!factor) return res.status(400).json({ error: 'Unknown factor' });

    const valid = authenticator.check(code, factor.secret);
    if (!valid) return res.status(401).json({ error: 'Incorrect code' });

    const { rows: userRows } = await pool.query('select id, email from auth.users where id = $1', [factor.user_id]);
    const authUser = userRows[0];
    if (!authUser) return res.status(404).json({ error: 'User not found' });

    const profile = await getProfile(authUser.id);
    return res.json(issueSession(authUser, profile));
  } catch (e) {
    console.error('mfa verify error', e);
    return res.status(500).json({ error: 'Something went wrong' });
  }
});

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

// Mirrors _sb.auth.getSession() + the user_profiles fetch boot() does in
// app.html — one call returning fresh profile data for the JWT's subject.
app.get('/auth/session', requireAuth, async (req, res) => {
  const profile = await getProfile(req.auth.sub);
  return res.json({ user: { id: req.auth.sub, email: req.auth.email, ...profile } });
});

// ─── INVOICE PDF STORAGE ────────────────────────────────────────────────
// Replaces Supabase Storage's `invoices` bucket. Not a general file-storage
// API — just the two things app.html's Invoice Manager actually does:
// upload a PDF when creating an invoice, and hand back a short-lived
// download link later. Files live on disk under uploads/invoices/, laid
// out the same way the old bucket was: "<client_id>/<invoice_id>.pdf".
const UPLOADS_DIR = path.join(__dirname, 'uploads', 'invoices');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function safeInvoicePath(raw) {
  const normalized = path.normalize(String(raw || '')).replace(/^(\.\.(\/|\\|$))+/, '');
  if (!normalized || normalized.includes('..') || path.isAbsolute(normalized)) return null;
  return normalized;
}

// Invoices belong to one client; the path's first segment is always that
// client's id (see createInvoice() in app.html), so this is enough to check
// without a DB round-trip — same access shape as the invoices RLS policies.
function canAccessInvoicePath(auth, invoicePath) {
  if (auth.app_role === 'admin' || auth.app_role === 'super_admin') return true;
  const clientSegment = invoicePath.split('/')[0];
  return !!auth.client_id && clientSegment === auth.client_id;
}

app.post('/storage/invoices', requireAuth, express.raw({ type: 'application/pdf', limit: '20mb' }), (req, res) => {
  if (req.auth.app_role !== 'admin' && req.auth.app_role !== 'super_admin') {
    return res.status(403).json({ error: 'Not allowed' });
  }
  const invoicePath = safeInvoicePath(req.query.path);
  if (!invoicePath) return res.status(400).json({ error: 'Invalid path' });
  const fullPath = path.join(UPLOADS_DIR, invoicePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, req.body);
  res.json({ path: invoicePath });
});

// Mirrors _sb.storage.from('invoices').createSignedUrl(path, 60): a link
// good for 60 seconds, usable without an Authorization header (it gets
// opened directly via window.open), because the token itself is the proof.
app.get('/storage/invoices/sign', requireAuth, (req, res) => {
  const invoicePath = safeInvoicePath(req.query.path);
  if (!invoicePath) return res.status(400).json({ error: 'Invalid path' });
  if (!canAccessInvoicePath(req.auth, invoicePath)) return res.status(403).json({ error: 'Not allowed' });
  const fullPath = path.join(UPLOADS_DIR, invoicePath);
  if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'Not found' });
  const token = jwt.sign({ path: invoicePath, purpose: 'invoice-download' }, JWT_SECRET, { expiresIn: 60 });
  res.json({ signedUrl: `${PUBLIC_BASE_URL}/storage/invoices/download?path=${encodeURIComponent(invoicePath)}&token=${token}` });
});

app.get('/storage/invoices/download', (req, res) => {
  const invoicePath = safeInvoicePath(req.query.path);
  const token = String(req.query.token || '');
  if (!invoicePath || !token) return res.status(400).json({ error: 'Missing path or token' });
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired link' });
  }
  if (payload.purpose !== 'invoice-download' || payload.path !== invoicePath) {
    return res.status(403).json({ error: 'Token does not match this file' });
  }
  const fullPath = path.join(UPLOADS_DIR, invoicePath);
  if (!fs.existsSync(fullPath)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/pdf');
  res.sendFile(fullPath);
});

const port = process.env.PORT || 8001;
app.listen(port, () => console.log(`supanta-api listening on :${port}`));
