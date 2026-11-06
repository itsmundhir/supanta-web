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
const { pool } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set — refusing to start.');
  process.exit(1);
}

function issueSession(authUser, profile) {
  const payload = {
    sub: authUser.id,
    email: authUser.email,
    role: profile ? profile.role : null,
    client_id: profile ? profile.client_id : null,
    full_name: profile ? profile.full_name : null,
  };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  return { token, user: payload };
}

async function getProfile(userId) {
  const { rows } = await pool.query(
    'select id, full_name, email, role, client_id, job_title, links, cookie_consent from public.user_profiles where id = $1',
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

const port = process.env.PORT || 8001;
app.listen(port, () => console.log(`supanta-api listening on :${port}`));
