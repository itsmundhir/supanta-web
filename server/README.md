# supanta-api (minimal, login-only)

A minimal replacement for Supabase Auth, built against a real `pg_dumpall`
restore of the paused Supabase project (restored and tested locally
2026-11-06). Verified end-to-end against real production data: bcrypt
password check, TOTP MFA verification, and JWT session issuance all
confirmed working against the actual `super_admin` account.

## Scope — read this before assuming more works than does

**This covers login only**: `POST /auth/login`, `POST /auth/mfa/verify`,
`GET /auth/session`. Nothing else. The rest of the dashboard (tickets,
chats, invoices, integrations, everything) still calls the Supabase JS
client directly in `app.html`/`home.html` and will not work until that
code is migrated too — this was an explicit, agreed scope cut to hit a
weekend deadline, not an oversight. See the main migration conversation
for the full plan.

## What's needed to actually make supanta.com log in again

1. **A reachable Postgres instance with this data loaded.** This was only
   built and tested against a local Postgres in a sandbox — it is not
   deployed anywhere reachable from the internet yet. Needs the OVHcloud
   server (or wherever this ends up) provisioned, reachable, and loaded
   via the same `pg_dumpall` restore process used locally.
2. **This API deployed and reachable** (same server, or elsewhere) —
   needs a real `JWT_SECRET` generated fresh (never reuse the local test
   value in `.env`), and `DATABASE_URL` pointed at the production Postgres
   instance.
3. **`home.html` patched**: `doLogin()` and `verifyLogin2fa()` currently
   call `window._sb.auth.signInWithPassword()` / `window._sb.auth.mfa.*`
   directly — these need to call this API instead (`POST /auth/login`,
   `POST /auth/mfa/verify`), storing the returned JWT instead of relying
   on the Supabase JS client's own session storage.
4. **`app.html` patched**: `boot()` currently calls `_sb.auth.getSession()`
   then queries `user_profiles` via `_sb.from(...)` — needs to read the
   JWT this API issues instead (`GET /auth/session`, or decode the JWT's
   claims directly) to build `currentUser`.
5. Redeploy both to Netlify once patched.

## Local testing

```
npm install
cp .env.example .env   # fill in DATABASE_URL and a real JWT_SECRET
npm start
```

`.env` is gitignored — never commit it. The local test password set for
the sandbox's own `postgres` role is not a secret worth protecting (throwaway
sandbox, destroyed with the session) but a real deployment's DB password and
`JWT_SECRET` must be generated fresh and never reused from any example here.
