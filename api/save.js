const crypto = require('node:crypto');

function verifySession(token, secret) {
  try {
    if (!token || typeof token !== 'string') return null;
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length !== 3) return null;
    const [username, expStr, sig] = parts;
    const expected = crypto.createHmac('sha256', secret)
      .update(`${username}:${expStr}`)
      .digest('hex');
    const sigBuf = Buffer.from(sig, 'utf8');
    const expBuf = Buffer.from(expected, 'utf8');
    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    const exp = parseInt(expStr, 10);
    if (!Number.isFinite(exp) || Date.now() > exp) return null;
    return { username, exp };
  } catch {
    return null;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const {
    SESSION_SECRET,
    GITHUB_TOKEN,
    GITHUB_REPO = 'atsebabi/Merkuz-',
    GITHUB_BRANCH = 'main',
    GITHUB_FILE_PATH = 'content.json',
  } = process.env;

  if (!SESSION_SECRET || !GITHUB_TOKEN) {
    return res.status(500).json({
      error: 'Server not configured. Set SESSION_SECRET and GITHUB_TOKEN in Vercel environment variables.',
    });
  }

  const body = req.body || {};
  const session = verifySession(body.token, SESSION_SECRET);
  if (!session) {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }

  if (!body.content || typeof body.content !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid content payload.' });
  }

  const newJson = JSON.stringify(body.content, null, 2) + '\n';
  const encoded = Buffer.from(newJson, 'utf8').toString('base64');

  const ghHeaders = {
    'Authorization': `Bearer ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'merkuz-admin-portal',
  };

  try {
    const metaRes = await fetch(
      `https://api.github.com/repos/${GITHUB_REPO}/contents/${GITHUB_FILE_PATH}?ref=${encodeURIComponent(GITHUB_BRANCH)}`,
      { headers: ghHeaders }
    );

    if (!metaRes.ok) {
      const err = await metaRes.json().catch(() => ({}));
      return res.status(502).json({
        error: `Could not read current content.json: ${err.message || metaRes.status}`,
      });
    }

    const meta = await metaRes.json();

    const putRes = await fetch(
      `https://api.github.com/repos/${GITHUB_REPO}/contents/${GITHUB_FILE_PATH}`,
      {
        method: 'PUT',
        headers: { ...ghHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: `Update landing page content via admin portal (${new Date().toISOString()})`,
          content: encoded,
          sha: meta.sha,
          branch: GITHUB_BRANCH,
          committer: {
            name: 'Merkuz Admin',
            email: 'admin@merkuz.org',
          },
        }),
      }
    );

    if (!putRes.ok) {
      const err = await putRes.json().catch(() => ({}));
      return res.status(502).json({
        error: err.message || `GitHub error (${putRes.status})`,
      });
    }

    const result = await putRes.json();
    return res.status(200).json({
      success: true,
      commitSha: result.commit?.sha,
      commitUrl: result.commit?.html_url,
    });
  } catch (err) {
    return res.status(502).json({ error: `Network error: ${err.message}` });
  }
};
