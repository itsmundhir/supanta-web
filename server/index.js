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
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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

// Mirrors is_internal_user() used by several Edge Functions: Supanta staff,
// or a user whose own client row is flagged account_type='internal'.
async function isInternalUser(userId) {
  const { rows } = await pool.query('select role, client_id from public.user_profiles where id = $1', [userId]);
  const profile = rows[0];
  if (!profile) return false;
  if (profile.role === 'admin' || profile.role === 'super_admin') return true;
  if (profile.client_id) {
    const { rows: clientRows } = await pool.query('select account_type from public.clients where id = $1', [profile.client_id]);
    return clientRows[0]?.account_type === 'internal';
  }
  return false;
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
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

// Mirrors _sb.auth.updateUser({password}) from the account settings page.
app.post('/auth/change-password', requireAuth, async (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const hash = await bcrypt.hash(password, 10);
  await pool.query('update auth.users set encrypted_password = $1, updated_at = now() where id = $2', [hash, req.auth.sub]);
  res.json({ ok: true });
});

// ─── MFA MANAGEMENT (settings page — enroll/verify/unenroll a TOTP factor) ──
// Mirrors _sb.auth.mfa.listFactors()/.enroll()/.challenge()/.verify()/.unenroll().
// Separate from /auth/mfa/verify above, which is the pre-login step during
// sign-in itself and doesn't require a Bearer token (the user isn't signed
// in yet at that point).
app.get('/auth/mfa/factors', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    "select id, status from auth.mfa_factors where user_id = $1 and factor_type = 'totp'",
    [req.auth.sub]
  );
  res.json({ totp: rows });
});

app.post('/auth/mfa/enroll', requireAuth, async (req, res) => {
  const secret = authenticator.generateSecret();
  const factorId = crypto.randomUUID();
  await pool.query(
    `insert into auth.mfa_factors (id, user_id, factor_type, status, secret, friendly_name, created_at, updated_at)
     values ($1, $2, 'totp', 'unverified', $3, 'Authenticator app', now(), now())`,
    [factorId, req.auth.sub, secret]
  );
  const otpauth = authenticator.keyuri(req.auth.email, 'Supanta', secret);
  const qrCode = await QRCode.toDataURL(otpauth);
  res.json({ id: factorId, totp: { qr_code: qrCode, secret } });
});

app.post('/auth/mfa/challenge', requireAuth, async (req, res) => {
  const factorId = String(req.body.factor_id || '');
  const { rows } = await pool.query(
    "select id from auth.mfa_factors where id = $1 and user_id = $2 and factor_type = 'totp'",
    [factorId, req.auth.sub]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Unknown factor' });
  // No separate challenge/response round-trip for TOTP (unlike push/SMS
  // factors) — the code itself is the proof, checked in /auth/mfa/enroll/verify.
  // This just mirrors supabase-js's two-call shape so app.html didn't need
  // to change at that call site.
  res.json({ id: factorId });
});

app.post('/auth/mfa/enroll/verify', requireAuth, async (req, res) => {
  const factorId = String(req.body.factor_id || '');
  const code = String(req.body.code || '').trim();
  const { rows } = await pool.query(
    "select secret from auth.mfa_factors where id = $1 and user_id = $2 and factor_type = 'totp'",
    [factorId, req.auth.sub]
  );
  const factor = rows[0];
  if (!factor) return res.status(404).json({ error: 'Unknown factor' });
  if (!authenticator.check(code, factor.secret)) return res.status(401).json({ error: 'Incorrect code' });
  await pool.query("update auth.mfa_factors set status = 'verified', updated_at = now() where id = $1", [factorId]);
  res.json({ ok: true });
});

app.post('/auth/mfa/unenroll', requireAuth, async (req, res) => {
  const factorId = String(req.body.factor_id || '');
  await pool.query('delete from auth.mfa_factors where id = $1 and user_id = $2', [factorId, req.auth.sub]);
  res.json({ ok: true });
});

// ─── ONBOARDING ──────────────────────────────────────────────────────────
// Mirrors the complete-onboarding Edge Function: finishes account setup for
// a brand-new self-serve signup. Refuses to run if the caller is already
// linked to a business, so it can only ever create one, never re-point an
// existing linkage. The signer-upper becomes 'client_admin' on their own
// business — the only role (besides Supanta staff) allowed to invite/promote
// teammates.
app.post('/onboarding/complete', requireAuth, async (req, res) => {
  const { rows } = await pool.query('select client_id, role, full_name from public.user_profiles where id = $1', [req.auth.sub]);
  const profile = rows[0];
  if (profile?.client_id) return res.status(400).json({ error: 'Your account is already linked to a business' });
  if (profile?.role === 'admin' || profile?.role === 'super_admin') {
    return res.status(400).json({ error: "Staff accounts can't self-onboard a business" });
  }

  const companyName = String(req.body.company_name || '').trim();
  const service = String(req.body.service || '').trim();
  const notes = String(req.body.notes || '').trim();
  if (!companyName) return res.status(400).json({ error: 'Company name is required' });

  try {
    const { rows: clientRows } = await pool.query(
      `insert into public.clients (user_id, company_name, contact_name, email, plan, status, currency, notes)
       values ($1, $2, $3, $4, 'Starter', 'onboarding', 'USD', $5) returning id`,
      [req.auth.sub, companyName, profile?.full_name || req.auth.email, req.auth.email,
        service ? `Service: ${service}${notes ? '\n' + notes : ''}` : (notes || null)]
    );
    const clientId = clientRows[0].id;
    await pool.query(
      "update public.user_profiles set client_id = $1, role = 'client_admin', company = $2, status = 'active' where id = $3",
      [clientId, companyName, req.auth.sub]
    );
    res.json({ success: true, client_id: clientId });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Could not create business record' });
  }
});

// ─── INVOICE NOTIFY (email) ──────────────────────────────────────────────
app.post('/invoices/notify', requireAuth, async (req, res) => {
  if (!(await isInternalUser(req.auth.sub))) {
    return res.status(403).json({ error: 'Only Supanta staff can send invoice notifications.' });
  }
  const postmarkToken = process.env.POSTMARK_API_TOKEN;
  const fromEmail = process.env.POSTMARK_FROM_EMAIL || 'billing@supanta.com';
  const invoiceId = String(req.body.invoice_id || '');
  if (!invoiceId) return res.status(400).json({ error: 'Missing invoice_id' });

  const { rows: invRows } = await pool.query('select * from public.invoices where id = $1', [invoiceId]);
  const invoice = invRows[0];
  if (!invoice) return res.status(404).json({ error: 'Invoice not found' });

  const { rows: clientRows } = await pool.query('select company_name, billing_emails, email from public.clients where id = $1', [invoice.client_id]);
  const client = clientRows[0];
  if (!client) return res.status(404).json({ error: 'Client not found' });

  let recipients = Array.isArray(client.billing_emails) ? client.billing_emails.filter(Boolean) : [];
  if (!recipients.length) {
    const { rows: admins } = await pool.query(
      "select email from public.user_profiles where client_id = $1 and role = 'client_admin'",
      [invoice.client_id]
    );
    recipients = admins.map((a) => a.email).filter(Boolean);
  }
  if (!recipients.length && client.email) recipients = [client.email];
  if (!recipients.length) return res.status(400).json({ error: 'This client has no billing contacts or admin emails on file to notify.' });

  if (!postmarkToken) {
    return res.status(500).json({ error: "Email isn't configured yet — POSTMARK_API_TOKEN is missing from the server's .env." });
  }

  const amountFmt = new Intl.NumberFormat('en-US', { style: 'currency', currency: invoice.currency || 'USD' }).format(Number(invoice.amount));
  const dueDateFmt = new Date(invoice.due_date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const html = `<!doctype html><html><body style="font-family:-apple-system,Helvetica,Arial,sans-serif;background:#f5f6f8;padding:32px 0;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;color:#1a1a1a">
    <h2 style="margin:0 0 16px;font-size:20px">New invoice from Supanta</h2>
    <p style="font-size:14px;line-height:1.6;color:#444">Hi ${escapeHtml(client.company_name)} team, a new invoice is ready for your account.</p>
    <table style="width:100%;font-size:14px;margin:20px 0;border-collapse:collapse">
      <tr><td style="padding:8px 0;color:#777">Invoice number</td><td style="padding:8px 0;text-align:right;font-weight:600">${escapeHtml(invoice.display_id)}</td></tr>
      <tr><td style="padding:8px 0;color:#777;border-top:1px solid #eee">Amount due</td><td style="padding:8px 0;text-align:right;font-weight:600;border-top:1px solid #eee">${escapeHtml(amountFmt)}</td></tr>
      <tr><td style="padding:8px 0;color:#777;border-top:1px solid #eee">Due date</td><td style="padding:8px 0;text-align:right;font-weight:600;border-top:1px solid #eee">${escapeHtml(dueDateFmt)}</td></tr>
    </table>
    ${invoice.payment_url ? `<a href="${escapeHtml(invoice.payment_url)}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-size:14px;font-weight:600">Pay this invoice</a>` : ''}
    <p style="font-size:13px;line-height:1.6;color:#777;margin-top:28px">You can also view and download this invoice from your Supanta dashboard under Invoices.</p>
    <p style="font-size:13px;color:#999;margin-top:32px;border-top:1px solid #eee;padding-top:16px">Smart Support. Real People.</p>
  </div>
  </body></html>`;
  const textBody = `New invoice from Supanta\n\nInvoice number: ${invoice.display_id}\nAmount due: ${amountFmt}\nDue date: ${dueDateFmt}\n${invoice.payment_url ? `Pay: ${invoice.payment_url}\n` : ''}\nView and download this invoice from your Supanta dashboard under Invoices.\n\nSmart Support. Real People.`;

  try {
    const pmRes = await fetch('https://api.postmarkapp.com/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Postmark-Server-Token': postmarkToken },
      body: JSON.stringify({ From: fromEmail, To: recipients.join(', '), Subject: 'New invoice from Supanta', HtmlBody: html, TextBody: textBody, MessageStream: 'outbound' }),
    });
    if (!pmRes.ok) {
      const t = await pmRes.text();
      return res.status(400).json({ error: `Postmark send failed: ${pmRes.status} ${t.slice(0, 300)}` });
    }
    res.json({ success: true, sent_to: recipients });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ─── INVOICE PDF FIELD EXTRACTION (Claude) ───────────────────────────────
const EXTRACT_TOOL = {
  name: 'extracted_invoice_fields',
  description: "The invoice number, amount, currency, issue date, and due date read from the attached PDF. Leave a field null if it isn't present or legible in the document — never guess a value.",
  input_schema: {
    type: 'object',
    properties: {
      invoice_number: { type: ['string', 'null'], description: 'The invoice number/reference as printed on the document' },
      amount: { type: ['number', 'null'], description: 'The total amount due, as a plain number with no currency symbol or separators' },
      currency: { type: ['string', 'null'], description: '3-letter ISO currency code, e.g. USD, EUR, GBP' },
      issue_date: { type: ['string', 'null'], description: 'Issue date in YYYY-MM-DD format' },
      due_date: { type: ['string', 'null'], description: 'Due date in YYYY-MM-DD format' },
    },
    required: ['invoice_number', 'amount', 'currency', 'issue_date', 'due_date'],
  },
};

app.post('/invoices/extract-pdf', requireAuth, async (req, res) => {
  if (!(await isInternalUser(req.auth.sub))) {
    return res.status(403).json({ error: 'Only Supanta staff can use invoice extraction.' });
  }
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (!anthropicKey) {
    return res.status(500).json({ error: "Extraction isn't configured yet — ANTHROPIC_API_KEY is missing from the server's .env." });
  }
  const pdfBase64 = String(req.body.pdf_base64 || '');
  if (!pdfBase64) return res.status(400).json({ error: 'Missing pdf_base64' });
  if (pdfBase64.length > 7_000_000) return res.status(400).json({ error: 'That PDF is too large to extract from (max ~5MB).' });

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 500,
        system: 'You read invoice/billing PDFs and extract structured fields. Only report what is actually printed in the document — use null for anything missing, unclear, or ambiguous. Never infer or estimate a value.',
        tools: [EXTRACT_TOOL],
        tool_choice: { type: 'tool', name: 'extracted_invoice_fields' },
        messages: [{
          role: 'user',
          content: [
            { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 } },
            { type: 'text', text: 'Extract the invoice number, amount, currency, issue date, and due date from this document.' },
          ],
        }],
      }),
    });
    if (!resp.ok) {
      const t = await resp.text();
      return res.status(400).json({ error: `Claude API error (${resp.status}): ${t.slice(0, 300)}` });
    }
    const data = await resp.json();
    const toolUse = (data.content || []).find((c) => c.type === 'tool_use');
    if (!toolUse) return res.status(400).json({ error: 'Could not extract fields from that PDF.' });
    res.json({ fields: toolUse.input });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// ─── PUBLIC ARIA WIDGET (marketing site, anonymous visitors) ────────────
// No auth — this is deliberately separate from the dashboard's own
// client-assistant logic, and only ever answers from one client's public
// knowledge_base rows (never ticket/team data).
const ARIA_ESCALATE_MARKER = '[ESCALATE]';
const ARIA_SYSTEM_PROMPT = `You are ARIA, the AI assistant on Supanta's public marketing website, talking to an anonymous visitor who has not signed up yet.

Tone: professional, warm, concise. No emojis, no hype language, no exclamation points.

Hard rules:
- Answer only using the KNOWLEDGE BASE block below. If something isn't covered there, say you don't have that detail and offer to connect them with the team — never invent facts about Supanta.
- Supanta does not publish pricing. If asked about pricing/cost, say pricing isn't published and offer to connect them with the team for a tailored quote.
- You cannot take real actions (no bookings, no account creation, no ticket filing). If the visitor wants to move forward (book a call, get a quote, talk to a person, or asks something outside the knowledge base), say you'll pass them to the team.
- Keep replies short — 2-4 sentences unless the question genuinely needs more.
- After your reply, on its own new line, output exactly "${ARIA_ESCALATE_MARKER}" if the visitor should be connected with a human (pricing, booking a call/demo, wanting to talk to someone, or a question outside the knowledge base). Otherwise do not output that line at all.`;

app.post('/public/aria-query', async (req, res) => {
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const message = String(req.body.message || '').slice(0, 1000);
  const clientId = String(req.body.client_id || '');
  const sessionId = String(req.body.session_id || '').slice(0, 100);
  if (!message) return res.status(400).json({ error: 'Missing message' });
  if (!clientId) return res.status(400).json({ error: 'Missing client_id' });

  const { rows: clientRows } = await pool.query('select company_name from public.clients where id = $1', [clientId]);
  const client = clientRows[0];
  if (!client) return res.status(404).json({ error: 'Unknown client' });

  const { rows: kb } = await pool.query(
    `select title, content, category from public.knowledge_base
     where client_id = $1 and is_active = true and approval_status = 'approved' limit 30`,
    [clientId]
  );
  const kbText = kb.length
    ? kb.map((k) => `- [${k.category ?? 'General'}] ${k.title}: ${String(k.content ?? '').slice(0, 600)}`).join('\n')
    : 'No knowledge base entries available.';

  if (!anthropicKey) {
    return res.status(500).json({ error: "ARIA isn't fully configured yet — missing ANTHROPIC_API_KEY." });
  }

  const history = Array.isArray(req.body.history)
    ? req.body.history.slice(-6).filter((h) => h && (h.role === 'user' || h.role === 'assistant') && typeof h.content === 'string').map((h) => ({ role: h.role, content: String(h.content).slice(0, 1000) }))
    : [];

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 400,
        system: `${ARIA_SYSTEM_PROMPT}\n\nKNOWLEDGE BASE:\n${kbText}`,
        messages: [...history, { role: 'user', content: message }],
      }),
    });
    if (!resp.ok) {
      const t = await resp.text();
      return res.status(500).json({ error: `Claude error: ${resp.status} ${t.slice(0, 200)}` });
    }
    const data = await resp.json();
    const block = (data.content || []).find((c) => c.type === 'text');
    let reply = block?.text || "Sorry, I couldn't generate a response just now.";

    let escalated = false;
    if (reply.includes(ARIA_ESCALATE_MARKER)) {
      escalated = true;
      reply = reply.replace(ARIA_ESCALATE_MARKER, '').trim();
    }

    if (sessionId) {
      pool.query(
        'insert into public.audit_log (actor_name, action, type) values ($1, $2, $3)',
        [`Anonymous visitor (${sessionId.slice(0, 12)})`, `Public ARIA widget query on ${client.company_name}: "${message.slice(0, 120)}"`, 'info']
      ).catch(() => {});
    }

    res.json({ response: reply, escalated });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.get('/public/aria-quick-questions', async (req, res) => {
  const clientId = String(req.query.client_id || '');
  if (!clientId) return res.status(400).json({ error: 'Missing client_id' });
  const { rows } = await pool.query(
    'select id, question, answer from public.client_quick_questions where client_id = $1 order by position asc limit 6',
    [clientId]
  );
  res.json({ questions: rows.map((q) => ({ id: q.id, question: q.question, answer: q.answer || null })) });
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
