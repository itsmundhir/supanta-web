# Supanta Website — Audit Report

## Executive Summary

`supanta-web` is a single 2,408-line static `index.html` file (~280KB) — a marketing
site, careers page, client login, and admin/client portal all built as one
client-rendered "SPA" with no server, no build tooling, no CI/CD, and no
package manifest. It talks to a real Supabase backend (project `qzpairbwdmozntmsaryq`)
for jobs, clients, conversations, and messages.

Because of this architecture, most items in a conventional audit checklist
(SQL injection, Docker, CI/CD, dependency bloat, ORM/query efficiency, database
design review) **don't apply** — there is no server code and no dependency
manifest to audit. This report focuses on what's real and verifiable, and the
fixes below have been implemented and pushed to
`claude/supanta-web-audit-8ijwe0`.

## Confirmed via Supabase (live project)

- RLS is **enabled on all 20 tables** (`user_profiles`, `clients`, `conversations`,
  `messages`, `job_posts`, `applications`, etc.) — good.
- Advisor warnings (not fixed, requires a decision from you since they touch
  production auth config):
  - **Leaked password protection is disabled** in Supabase Auth. Recommend
    enabling it (Auth → Policies) to reject known-compromised passwords.
  - Four `SECURITY DEFINER` functions (`get_my_role`, `handle_new_user`,
    `is_admin`, `my_client_id`) are callable by `anon`/`authenticated` roles.
    These look like intentional helper functions for RLS policies (they only
    expose the caller's own role/client), but worth a manual review to confirm
    none leaks cross-tenant data.
- The Supabase anon key embedded in `index.html` (line ~995) is expected to be
  public — it's meaningless without RLS, and RLS is on. Not a vulnerability.

## Fixes implemented (this session)

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 1 | `submitPwd()` referenced a `USERS` object that is **never defined anywhere** in the file — a leftover from before the app was migrated to Supabase Auth. Every "confirm with password" action (save content, add employee, delete FAQ/position, toggle staff status, save permissions) threw `ReferenceError` and silently failed. | **Critical (functional bug)** | Rewired `submitPwd()` to re-authenticate the current user against Supabase (`signInWithPassword`), matching the pattern already used by the real login flow. |
| 2 | `resendLoginDetails()`, `toggleClientUser()`, `execAddEmployee()` also referenced the same non-existent `USERS` object, which would throw and abort those admin actions. | High (functional bug) | Removed the dead `USERS` references; duplicate-email check in `execAddEmployee` now checks the in-memory `STAFF` list instead. |
| 3 | Public ARIA chat widget (`sendAriaMsg`) inserted the visitor's own typed message into the DOM via `innerHTML` unescaped — a self-XSS vector (`<img src=x onerror=...>` executes in the visitor's own browser). | High | Added `escapeHtml()` helper, applied to both the user's message and the canned bot reply. |
| 4 | `renderConvoMsg()` inserts `message.content` — real customer/agent chat content fetched from Supabase — via `innerHTML` unescaped, in the admin portal's conversation viewer. | High | Escaped with `escapeHtml()`. |
| 5 | Public FAQ section (`applyFaqToPage`) renders `FAQ_DATA` question/answer text via `innerHTML` unescaped; content is admin-editable, so a compromised or careless admin session could inject persistent script into a page every visitor loads. | Medium | Escaped with `escapeHtml()`. |
| 6 | No `<meta name="description">`, Open Graph, Twitter Card, canonical link, or `robots` tag. No `robots.txt` / `sitemap.xml`. | Medium (SEO) | Added description, OG/Twitter tags, canonical link, `robots.txt`, and a `sitemap.xml` scoped to the one real URL the site has (see Architecture finding below — don't list fake sub-paths that 404). |
| 7 | No skip-to-content link; primary/mobile nav built from `<a>` tags with `onclick` and no `href` — not part of the Tab order and not activatable with Enter/Space by default. Icon-only buttons (hamburger, chat close/open) had no accessible name. Login/password-reset `<label>`s weren't associated with their inputs (`for`/`id`). | Medium (a11y, WCAG 2.2) | Added a skip link + `#main-content` landmark, `role="link"`/`role="button"` + `tabindex="0"` on JS-driven nav/FAQ elements plus a delegated keydown handler so Enter/Space activate them, `aria-label`s on icon buttons, `aria-expanded` on the hamburger, `for=`/`autocomplete` on all auth form labels/inputs, and `:focus-visible` outlines. Verified in a headless browser: Enter now opens pages via nav links and toggles the FAQ. |
| 8 | Duplicate CSS rule (`#page-home{display:block}` declared twice on the same line). | Low (code quality) | Removed the duplicate. |

All changes were verified with `node --check` on the extracted inline script (no syntax errors), an HTML tag-balance check, and headless-browser tests (navigation, keyboard activation, and the XSS payload rendering as inert text instead of executing).

## Findings not fixed (flagged for a decision, not code bugs)

- **No client-side routing.** `goTo()` only toggles `display:none`/`block` — the
  URL never changes (no `history.pushState`, no hash routing). This means:
  - `/about`, `/services`, `/careers`, `/contact` are not real, bookmarkable,
    shareable URLs — everything is `https://supanta.com/`.
  - Browser back/forward doesn't move between sections.
  - Search engines can only ever index one URL; a "sitemap" listing those
    sub-paths would be actively misleading since they don't resolve.
  - **Recommendation:** if SEO/shareable deep links matter, add real routing
    (even simple hash routes with `pushState`) before investing further in
    per-page SEO metadata.
- **Client-side "authorization"** (`isCEO()`, `hasAccess()`, admin tab
  visibility) is enforced only in JS/CSS, which is normal for an SPA — real
  enforcement is Supabase RLS, which is confirmed on. No action needed beyond
  periodically re-running the RLS/advisor check after schema changes.
- **Architecture**: the admin portal (`STAFF`, `POSITIONS`, `CLIENT_COMPANIES`,
  `AUDIT`, `FAQ_DATA`) runs on hardcoded in-memory demo arrays that reset on
  reload — it is not actually wired to Supabase for most admin CRUD (only
  jobs/clients/messages are read from Supabase for display). This is fine for
  a demo/pitch build but means "Add Employee", "Deactivate account", etc. are
  currently cosmetic and won't persist. Worth confirming with you whether this
  is intentional (sales demo) or should be wired to real tables before
  production use.
- **Color contrast**: body copy uses `--grey: #8a9ab5` on `--dark: #050d1a`
  (~5.5:1) — passes WCAG AA for normal text but not AAA. Not changed, since
  it's a brand color decision; flagging for awareness.
- **No CI/CD, tests, Docker, or dependency manifest** exist because this is a
  static single file with zero build step. Nothing to fix here without first
  deciding whether to introduce tooling (e.g., splitting into real files with
  a bundler) — that's a larger architecture decision I did not make unilaterally.

## Quick wins still available (under 1 hour each, not done — flag if you want them)

- Add a real Open Graph image (`og:image`) — none exists in the repo.
- Enable Supabase leaked-password protection (Auth dashboard setting).
- Add `aria-label`s to the remaining icon-only buttons in the portal (modal
  close `✕` buttons, sidebar icons) — same pattern as the fixes above, just
  more surface area than time allowed to fully sweep in this pass.

## What I deliberately did not do

I did not attempt a full visual redesign, did not introduce a build system,
framework, or file-split refactor, and did not touch production Supabase Auth
settings — those are all real, larger decisions (visual identity, hosting
model, auth policy) that should be confirmed with you first rather than
pushed silently in an automated audit pass.
