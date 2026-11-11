const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const Core = require('./scanner-core.js');
const { createEngine } = require('./engine.js');

const b64url = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function message(id, o = {}) {
  return {
    id, threadId: 't' + id, labelIds: ['INBOX'], internalDate: String(Date.now()),
    payload: {
      mimeType: 'text/plain',
      headers: [
        { name: 'From', value: o.from || 'Bob <bob@example.com>' }, { name: 'Subject', value: 'Hi' },
        { name: 'Authentication-Results', value: o.auth || 'mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com' }
      ],
      body: { data: b64url(o.body || 'Lunch?') }
    }
  };
}
function env(messages, o = {}) {
  const calls = [];
  const fetchFn = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || 'GET', body: opts.body });
    const json = (status, body) => ({ ok: status < 400, status, json: async () => body });
    if (url.includes('rdap.org')) return json(200, { events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - (o.rdapDays || 3000) * 86400000).toISOString() }] });
    if (url.includes('safebrowsing')) return json(200, o.sbMatches ? { matches: o.sbMatches } : {});
    if (url.includes('/threads/') && url.includes('/modify')) return json(200, {});
    const m = url.match(/\/messages\/([^/?]+)/);
    if (m && messages[m[1]]) return json(200, messages[m[1]]);
    if (url.includes('/messages?')) return json(200, { messages: o.history || [{ id: 'older' }] });
    return json(404, { error: { message: 'nf' } });
  };
  return { calls, env: { fetch: fetchFn, getToken: async () => 'tok', getSettings: async () => ({ keys: { SAFE_BROWSING_API_KEY: o.sbKey || '' }, config: {} }) } };
}

test('benign message is green and uses the shared core', async () => {
  const { env: e } = env({ a: message('a') });
  const r = await createEngine(e).scanMessage('a', false);
  assert.strictEqual(r.level, 'green', JSON.stringify(r.findings));
});

test('spoofed brand mail with a flagged link is not green', async () => {
  const m = message('b', { from: 'PayPal <x@paypa1-help.xyz>', auth: 'mx.google.com; spf=fail; dkim=none; dmarc=fail header.from=paypa1-help.xyz', body: 'Urgent verify now http://paypa1-help.xyz/a' });
  const { env: e, calls } = env({ b: m }, { sbKey: 'k', rdapDays: 1, sbMatches: [{ threatType: 'SOCIAL_ENGINEERING', threat: { url: 'http://paypa1-help.xyz/a' } }] });
  const r = await createEngine(e).scanMessage('b', false);
  assert.strictEqual(r.level, 'red');
  const sb = calls.find((c) => c.url.includes('safebrowsing'));
  assert.ok(!sb.url.includes('key='), 'API key must not be in the URL');
});

test('missing key and unavailable redirects are reported as not checked', async () => {
  const m = message('c', { body: 'see https://bit.ly/x' });
  const { env: e } = env({ c: m });
  const r = await createEngine(e).scanMessage('c', false);
  assert.ok(r.incomplete);
  assert.ok(r.skipped.some((s) => /Safe Browsing/.test(s)));
  assert.ok(r.skipped.some((s) => /Redirect/.test(s)));
});

test('API failure rejects instead of returning a clean result', async () => {
  const { env: e } = env({});
  await assert.rejects(createEngine(e).scanMessage('missing', false), /Gmail API 404/);
});

test('neutralize only adds SPAM and never trashes', async () => {
  const { env: e, calls } = env({});
  await createEngine(e).neutralize('t1');
  const body = JSON.parse(calls[0].body);
  assert.deepStrictEqual(body.addLabelIds, ['SPAM']);
  assert.ok(!calls[0].body.includes('TRASH'));
});

test('manifest needs no OAuth and stays least-privilege', () => {
  const man = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));
  assert.strictEqual(man.oauth2, undefined, 'no OAuth client should be needed');
  assert.deepStrictEqual(man.permissions, ['storage', 'activeTab']);
  assert.ok(!man.host_permissions.some((h) => /gmail\.googleapis|vision|virustotal/.test(h)));
  assert.deepStrictEqual(man.content_scripts[0].matches, ['https://mail.google.com/*']);
  assert.notStrictEqual(man.background.type, 'module');
  const bg = fs.readFileSync(path.join(__dirname, 'background.js'), 'utf8');
  assert.ok(bg.includes("importScripts('scanner-core.js', 'mime.js', 'engine.js')"));
  const files = ['popup.html', 'options.html', 'mime.js', 'engine.js', 'scanner-core.js']
    .concat(man.content_scripts[0].js, man.web_accessible_resources[0].resources);
  for (const f of files) assert.ok(fs.existsSync(path.join(__dirname, f)), f);
});

test('UI renders email data via textContent only', () => {
  for (const f of ['popup.js', 'content.js', 'view.js', 'options.js']) {
    const src = fs.readFileSync(path.join(__dirname, f), 'utf8');
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser/.test(src), f);
  }
});
