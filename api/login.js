const { safeEqual, signSession } = require('./_lib/session');

const FAILED_LOGIN_DELAY_MS = 1000;

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
  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  // Evaluate both comparisons so timing doesn't reveal which one failed.
  const userOk = safeEqual(username, ADMIN_USERNAME);
  const passOk = safeEqual(password, ADMIN_PASSWORD);
  if (!userOk || !passOk) {
    // Slow down password guessing. Serverless instances share no state, so
    // this is not a real rate limit — pair it with a Vercel Firewall rule.
    await new Promise((resolve) => setTimeout(resolve, FAILED_LOGIN_DELAY_MS));
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const { token, expiresAt } = signSession(username, SESSION_SECRET);
  return res.status(200).json({ token, expiresAt });
};
