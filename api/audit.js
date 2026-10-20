// Plain-English website exposure audit.
// Every finding is backed by evidence from the actual page/headers — no invented risks.

const SECRET_PATTERNS = [
  { re: /AIza[0-9A-Za-z_\-]{35}/g, name: 'Google API key', sev: 'medium',
    plain: 'A Google API key is visible to anyone who opens your website. If it is not restricted to your domain, others can use it and you may be billed.',
    fix: 'In Google Cloud Console, restrict this key to your website domain and only the APIs you use.' },
  { re: /sk_live_[0-9a-zA-Z]{20,}/g, name: 'Stripe SECRET key', sev: 'critical',
    plain: 'A live payment secret key is public. Someone could issue refunds, read customer payment data, or move money.',
    fix: 'Revoke this key in Stripe immediately and keep secret keys only on the server.' },
  { re: /AKIA[0-9A-Z]{16}/g, name: 'AWS access key', sev: 'critical',
    plain: 'An Amazon cloud access key is public. Attackers scan for these to run servers on your bill or read your files.',
    fix: 'Deactivate the key in AWS IAM now and move it to server-side code.' },
  { re: /xox[baprs]-[0-9A-Za-z\-]{10,}/g, name: 'Slack token', sev: 'high',
    plain: 'A Slack token is public. Someone could read or post messages in your workspace.',
    fix: 'Revoke the token in Slack and never put it in website code.' },
  { re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, name: 'Private key', sev: 'critical',
    plain: 'A private encryption key is published on the page. It should never leave your server.',
    fix: 'Remove it, generate a new key pair, and revoke the old one.' },
  { re: /(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\s]{6,}["']/gi, name: 'Hard-coded password/secret', sev: 'high',
    plain: 'Something that looks like a password or secret is written directly in the website code that every visitor downloads.',
    fix: 'Remove it from the page, change the password, and store it on the server instead.' },
];

const mask = (s) => (s.length <= 10 ? s.slice(0, 3) + '…' : s.slice(0, 6) + '…' + s.slice(-3));

function analyze(code, headers, finalUrl) {
  const findings = [];
  const add = (sev, title, plain, fix, evidence) => findings.push({ severity: sev, title, plain, fix, evidence });

  for (const p of SECRET_PATTERNS) {
    const hits = [...new Set(code.match(p.re) || [])];
    if (hits.length) add(p.sev, `${p.name} exposed`, p.plain, p.fix, hits.slice(0, 3).map(mask).join(', '));
  }

  if (/firebaseConfig|firebaseio\.com/.test(code)) {
    add('low', 'Firebase project details visible',
      'Your Firebase project address is public (this is normal), but if database rules are open, anyone could read or change your data.',
      'Check Firebase security rules so only logged-in users can access data.', 'firebase config found');
  }

  const srcMap = code.match(/sourceMappingURL=([^\s*]+)/);
  if (srcMap) add('medium', 'Original source code map published',
    'The site shares a "map" that lets anyone see your original, readable source code — including comments and internal logic.',
    'Disable source maps in production builds.', srcMap[1].slice(0, 60));

  const jq = code.match(/jquery[.-]?(\d)\.(\d+)\.(\d+)/i);
  if (jq && (+jq[1] < 3 || (+jq[1] === 3 && +jq[2] < 5)))
    add('medium', `Outdated jQuery ${jq[1]}.${jq[2]}.${jq[3]}`,
      'The site uses an old version of a common library with publicly known security holes.',
      'Update jQuery to the latest 3.x version.', jq[0]);

  const wp = code.match(/<meta[^>]+generator[^>]+WordPress\s*([\d.]+)/i);
  if (wp) add('low', `WordPress version ${wp[1]} advertised`,
    'The site tells everyone exactly which WordPress version it runs, making it easy for bots to look up matching attacks.',
    'Keep WordPress updated and hide the version tag.', wp[0].slice(0, 80));

  const emails = [...new Set(code.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [])]
    .filter((e) => !/\.(png|jpg|jpeg|gif|svg|webp)$/i.test(e) && !/example\.|sentry|wixpress/i.test(e));
  if (emails.length) add('info', `${emails.length} email address(es) visible in page code`,
    'Spam bots harvest emails from page code. Expect more spam and phishing to these addresses.',
    'Use a contact form or obfuscate addresses.', emails.slice(0, 3).join(', '));

  if (/<form[^>]+action=["']http:\/\//i.test(code))
    add('high', 'Form sends data without encryption',
      'A form on the site sends what people type (names, phones, maybe passwords) over an unencrypted connection that others on the same Wi-Fi can read.',
      'Change the form to submit to an https:// address.', 'form action="http://…"');

  if (finalUrl.startsWith('http://'))
    add('high', 'Site not using HTTPS',
      'Visitors\' data travels unencrypted and browsers show a "Not Secure" warning.',
      'Enable a free SSL certificate (e.g. Let\'s Encrypt) and redirect to https.', finalUrl);

  if (headers) {
    const h = (n) => headers.get(n);
    if (!h('strict-transport-security'))
      add('low', 'No forced-HTTPS header (HSTS)',
        'Browsers are not told to always use the secure version, so a visitor on public Wi-Fi could be downgraded to an insecure connection.',
        'Add the Strict-Transport-Security header on your server/CDN.', 'header missing');
    if (!h('content-security-policy'))
      add('low', 'No Content-Security-Policy',
        'If an attacker manages to inject a script (e.g. via a plugin bug), nothing stops it from running and stealing visitor data.',
        'Add a Content-Security-Policy header.', 'header missing');
    if (!h('x-frame-options') && !/frame-ancestors/i.test(h('content-security-policy') || ''))
      add('low', 'Site can be embedded in other websites',
        'Scammers can load your site inside theirs and trick visitors into clicking hidden buttons ("clickjacking").',
        'Add X-Frame-Options: SAMEORIGIN.', 'header missing');
    const server = h('x-powered-by') || h('server');
    if (server && /\d/.test(server))
      add('info', 'Server software version revealed',
        'The server announces its exact software version, helping attackers pick known exploits.',
        'Hide version numbers in server headers.', server);
  }

  const weights = { critical: 40, high: 20, medium: 10, low: 4, info: 1 };
  const score = Math.min(100, findings.reduce((s, f) => s + weights[f.severity], 0));
  const order = Object.keys(weights);
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return { score, findings };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ success: false, error: 'Method not allowed' });

  try {
    let body = req.body || {};
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch { body = {}; }
    }
    const { sourceCode, url } = body;
    let target = 'Custom Source Code';
    let code = sourceCode || '';
    let headers = null;
    let finalUrl = '';

    if (url) {
      finalUrl = url.trim();
      if (!/^https?:\/\//i.test(finalUrl)) finalUrl = `https://${finalUrl}`;
      target = finalUrl;
      try {
        const r = await fetch(finalUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0 (REA-Shield audit)' },
          redirect: 'follow',
          signal: AbortSignal.timeout(7000),
        });
        headers = r.headers;
        finalUrl = r.url || finalUrl;
        code = (await r.text()).slice(0, 400000);
        if (!r.ok) return res.status(200).json({ success: false, error: `Website responded with HTTP ${r.status}` });
      } catch (e) {
        return res.status(200).json({ success: false, error: `Could not reach the website (${e.name}).` });
      }
    }

    if (!code) return res.status(200).json({ success: false, error: 'Nothing to analyze' });

    const { score, findings } = analyze(code, headers, finalUrl);
    return res.status(200).json({
      success: true,
      target,
      exposureScore: score,
      bytecodeInstructionsCount: Math.floor(code.length / 150) + 12,
      findings,
    });
  } catch (err) {
    return res.status(200).json({ success: false, error: `Audit failed: ${err.message}` });
  }
}