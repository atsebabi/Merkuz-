// Shared helpers for the admin API. Files under api/_lib are not deployed as
// routes by Vercel (the leading underscore excludes them).
const crypto = require('node:crypto');

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h

function hmac(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// Constant-time comparison that does not leak the length of either value.
function safeEqual(a, b) {
  const aHash = crypto.createHash('sha256').update(String(a ?? ''), 'utf8').digest();
  const bHash = crypto.createHash('sha256').update(String(b ?? ''), 'utf8').digest();
  return crypto.timingSafeEqual(aHash, bHash);
}

function signSession(username, secret) {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = `${username}:${expiresAt}`;
  return {
    token: Buffer.from(`${payload}:${hmac(secret, payload)}`, 'utf8').toString('base64'),
    expiresAt,
  };
}

// Token format: base64("<username>:<expiresAt>:<hex signature>").
// The username may itself contain ':', so split from the right.
function verifySession(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const decoded = Buffer.from(token, 'base64').toString('utf8');
  const sigSep = decoded.lastIndexOf(':');
  const expSep = decoded.lastIndexOf(':', sigSep - 1);
  if (sigSep <= 0 || expSep <= 0) return null;

  const payload = decoded.slice(0, sigSep);
  const sig = decoded.slice(sigSep + 1);
  if (!safeEqual(sig, hmac(secret, payload))) return null;

  const expiresAt = Number(decoded.slice(expSep + 1, sigSep));
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return null;

  return { username: decoded.slice(0, expSep), expiresAt };
}

// Reads the session token from "Authorization: Bearer <token>".
function getSession(req, secret) {
  const header = req.headers?.authorization || '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? verifySession(match[1].trim(), secret) : null;
}

function githubConfig(env = process.env) {
  return {
    token: env.GITHUB_TOKEN,
    repo: env.GITHUB_REPO || 'atsebabi/Merkuz-',
    branch: env.GITHUB_BRANCH || 'main',
    path: env.GITHUB_FILE_PATH || 'content.json',
  };
}

function githubHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'merkuz-admin-portal',
  };
}

// Turns a failed GitHub API response into a message an admin can act on.
async function describeGithubError(res, action) {
  const body = await res.json().catch(() => ({}));
  const detail = body.message || `HTTP ${res.status}`;
  if (res.status === 401) {
    return `${action}: GitHub rejected the access token (${detail}). ` +
      'The GITHUB_TOKEN in Vercel has expired or been revoked — replace it and redeploy.';
  }
  if (res.status === 403 || res.status === 404) {
    return `${action}: GitHub denied access (${detail}). ` +
      'Check that GITHUB_TOKEN has "Contents: Read and write" access to the repository.';
  }
  if (res.status === 409) {
    return 'The content was changed by someone else since you loaded it.';
  }
  return `${action}: ${detail}`;
}

module.exports = {
  safeEqual,
  signSession,
  verifySession,
  getSession,
  githubConfig,
  githubHeaders,
  describeGithubError,
};
