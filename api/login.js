const crypto = require('node:crypto');

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h

function safeEqual(a, b) {
  const aBuf = Buffer.from(String(a || ''), 'utf8');
  const bBuf = Buffer.from(String(b || ''), 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function signSession(username, secret) {
  const exp = Date.now() + SESSION_TTL_MS;
  const payload = `${username}:${exp}`;
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return {
    token: Buffer.from(`${payload}:${sig}`, 'utf8').toString('base64'),
    expiresAt: exp,
  };
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { ADMIN_USERNAME, ADMIN_PASSWORD, SESSION_SECRET } = process.env;
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !SESSION_SECRET) {
    return res.status(500).json({
      error: 'Server not configured. Set ADMIN_USERNAME, ADMIN_PASSWORD, and SESSION_SECRET in Vercel environment variables.',
    });
  }

  const body = req.body || {};
  const username = typeof body.username === 'string' ? body.username : '';
  const password = typeof body.password === 'string' ? body.password : '';

  const userOk = safeEqual(username, ADMIN_USERNAME);
  const passOk = safeEqual(password, ADMIN_PASSWORD);

  if (!userOk || !passOk) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const { token, expiresAt } = signSession(username, SESSION_SECRET);
  return res.status(200).json({ token, expiresAt });
};
