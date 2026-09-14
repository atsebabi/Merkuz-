# Merkuz landing page

Static site for merkuz.org, hosted on Vercel.

| Path | Purpose |
| --- | --- |
| `index.html` | Public landing page. Default text is in the markup; on load it is replaced with `content.json`. |
| `content.json` | All editable site content. Written by the admin portal. |
| `admin.html` | Admin portal (`/admin.html`) for editing `content.json`. |
| `api/login.js` | Checks the admin username/password and issues a 24-hour session token. |
| `api/content.js` | Returns the latest `content.json` from GitHub for the admin portal. |
| `api/save.js` | Commits edited content to `content.json` on GitHub, which triggers a Vercel redeploy. |
| `api/_lib/session.js` | Shared session and GitHub helpers (not a route). |
| `vercel.json` | Security and caching headers (admin page is not indexed or frameable). |

## Vercel environment variables

| Variable | Required | Notes |
| --- | --- | --- |
| `ADMIN_USERNAME` | yes | Admin portal login. |
| `ADMIN_PASSWORD` | yes | Admin portal login. |
| `SESSION_SECRET` | yes | Long random string used to sign sessions. Changing it signs everyone out. |
| `GITHUB_TOKEN` | yes | Fine-grained personal access token with **Contents: Read and write** on this repository only. Tokens expire — note the date. |
| `GITHUB_REPO` | no | Defaults to `atsebabi/Merkuz-`. |
| `GITHUB_BRANCH` | no | Defaults to `main`. |
| `GITHUB_FILE_PATH` | no | Defaults to `content.json`. |

After changing any variable, redeploy the production deployment — running
deployments keep the old values.

If saving in the admin portal fails with "GitHub rejected the access token",
`GITHUB_TOKEN` has expired or been revoked: create a new one and redeploy.

## Notes

- **Signing out** clears the session in that browser only. A session token stays
  valid for up to 24 hours; to invalidate all sessions immediately, change
  `SESSION_SECRET` and redeploy.
- **Login attempts** are delayed by one second on failure, but serverless
  functions share no state. For real rate limiting, add a Vercel Firewall rate
  limit rule for `/api/login`.
- **Conflicts:** if someone else publishes while you are editing, the portal
  loads the latest content and re-applies your edits on top for review.
- **Fallback markup:** `index.html` contains a static copy of the content so the
  page renders before `content.json` loads (and for crawlers). It is not
  updated by the admin portal, so it drifts as content is edited; refresh it
  from `content.json` occasionally.
