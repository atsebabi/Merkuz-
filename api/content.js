// Returns the latest content.json straight from GitHub, plus its blob SHA.
// The admin panel edits this copy rather than the deployed /content.json,
// which lags behind GitHub until Vercel finishes redeploying.
const { getSession, githubConfig, githubHeaders, describeGithubError } = require('./_lib/session');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { SESSION_SECRET } = process.env;
  const gh = githubConfig();
  if (!SESSION_SECRET || !gh.token) {
    return res.status(500).json({
      error: 'Server not configured. Set SESSION_SECRET and GITHUB_TOKEN in Vercel environment variables.',
    });
  }

  if (!getSession(req, SESSION_SECRET)) {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }

  res.setHeader('Cache-Control', 'no-store');

  try {
    const ghRes = await fetch(
      `https://api.github.com/repos/${gh.repo}/contents/${gh.path}?ref=${encodeURIComponent(gh.branch)}`,
      { headers: githubHeaders(gh.token) }
    );
    if (!ghRes.ok) {
      return res.status(502).json({ error: await describeGithubError(ghRes, 'Could not read content.json') });
    }

    const file = await ghRes.json();
    const content = JSON.parse(Buffer.from(file.content, 'base64').toString('utf8'));
    return res.status(200).json({ content, sha: file.sha });
  } catch (err) {
    return res.status(502).json({ error: `Could not read content.json: ${err.message}` });
  }
};
