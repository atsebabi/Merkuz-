const { getSession, githubConfig, githubHeaders, describeGithubError } = require('./_lib/session');

const REQUIRED_SECTIONS = ['nav', 'hero', 'story', 'banner', 'services', 'programs', 'contact'];

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
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

  const { content, sha: clientSha } = req.body || {};
  if (!isPlainObject(content)) {
    return res.status(400).json({ error: 'Missing or invalid content payload.' });
  }
  // Guard against publishing a truncated document that would blank the site.
  const missing = REQUIRED_SECTIONS.filter((key) => !isPlainObject(content[key]));
  if (missing.length) {
    return res.status(400).json({ error: `Content is missing required sections: ${missing.join(', ')}.` });
  }

  const fileUrl = `https://api.github.com/repos/${gh.repo}/contents/${gh.path}`;
  const headers = githubHeaders(gh.token);

  try {
    // The client sends the SHA it loaded so GitHub rejects the write (409) if
    // the file changed in the meantime, instead of silently overwriting it.
    let sha = typeof clientSha === 'string' && clientSha ? clientSha : null;
    if (!sha) {
      const metaRes = await fetch(`${fileUrl}?ref=${encodeURIComponent(gh.branch)}`, { headers });
      if (!metaRes.ok) {
        return res.status(502).json({ error: await describeGithubError(metaRes, 'Could not read current content.json') });
      }
      sha = (await metaRes.json()).sha;
    }

    const putRes = await fetch(fileUrl, {
      method: 'PUT',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: `Update landing page content via admin portal (${new Date().toISOString()})`,
        content: Buffer.from(JSON.stringify(content, null, 2) + '\n', 'utf8').toString('base64'),
        sha,
        branch: gh.branch,
        committer: { name: 'Merkuz Admin', email: 'admin@merkuz.org' },
      }),
    });

    if (!putRes.ok) {
      const status = putRes.status === 409 ? 409 : 502;
      return res.status(status).json({ error: await describeGithubError(putRes, 'Could not publish content.json') });
    }

    const result = await putRes.json();
    return res.status(200).json({
      success: true,
      sha: result.content?.sha,
      commitSha: result.commit?.sha,
      commitUrl: result.commit?.html_url,
    });
  } catch (err) {
    return res.status(502).json({ error: `Network error: ${err.message}` });
  }
};
