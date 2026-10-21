/**
 * Apps Script add-on tests. Loads the real .gs files into a vm sandbox that mimics the Apps Script
 * runtime: no URL, no atob/btoa, no fetch, no Buffer. Only the services the code actually calls are
 * mocked, and the Gmail API is faked at the UrlFetchApp level so the whole path runs.
 */
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
const nodeCrypto = require('crypto');

const FILES = ['ScannerCore.gs', 'Config.gs', 'GmailApi.gs', 'Settings.gs', 'Enrichment.gs', 'UI.gs', 'Code.gs'];

function b64url(s) { return Buffer.from(s, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

function makeSandbox(fakeMessages, opts) {
  opts = opts || {};
  const calls = [];
  const store = {};
  const props = () => ({
    getProperty: (k) => (k in store ? store[k] : null),
    setProperty: (k, v) => { store[k] = String(v); }
  });
  const cacheData = {};
  const cache = { get: (k) => (k in cacheData ? cacheData[k] : null), put: (k, v) => { cacheData[k] = v; } };
  const response = (code, body, headers) => ({
    getResponseCode: () => code,
    getContentText: () => (typeof body === 'string' ? body : JSON.stringify(body)),
    getHeaders: () => headers || {}
  });
  const sandbox = {
    console,
    Math, Date, JSON, Array, Object, String, Number, RegExp, Error, parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent,
    ScriptApp: { getOAuthToken: () => 'test-token' },
    PropertiesService: { getUserProperties: props, getScriptProperties: props },
    CacheService: { getUserCache: () => cache, getScriptCache: () => cache },
    Utilities: {
      getUuid: () => nodeCrypto.randomUUID(),
      sleep: () => {},
      base64DecodeWebSafe: (s) => Array.from(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')).map((b) => (b > 127 ? b - 256 : b)),
      base64EncodeWebSafe: (b) => Buffer.from(b.map((x) => x & 255)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_'),
      base64Encode: (b) => Buffer.from(b.map((x) => x & 255)).toString('base64'),
      newBlob: (s) => ({ getBytes: () => Array.from(Buffer.from(s, 'utf8')).map((b) => (b > 127 ? b - 256 : b)) }),
      computeDigest: (alg, bytes) => Array.from(nodeCrypto.createHash('sha256').update(Buffer.from(bytes.map((x) => x & 255))).digest()).map((b) => (b > 127 ? b - 256 : b)),
      DigestAlgorithm: { SHA_256: 'sha256' }
    },
    UrlFetchApp: {
      fetch: (url, o) => {
        calls.push({ url, method: (o && o.method) || 'get', body: o && o.payload });
        const m = url.match(/\/messages\/([^/?]+)(?:\/attachments\/([^/?]+))?(?:\?format=(\w+))?/);
        if (url.indexOf('gmail.googleapis.com') >= 0) {
          if (url.indexOf('/labels') >= 0) return response(200, o.method === 'post' ? { id: 'Label_1' } : { labels: [] });
          if (url.indexOf('/threads/') >= 0) return response(200, {});
          if (url.indexOf('/drafts') >= 0) return response(200, { id: 'draft1' });
          if (m && m[2]) return response(200, { data: b64url('hello') });
          if (m && fakeMessages[m[1]]) {
            if (m[3] === 'raw') return response(200, { raw: b64url('From: a@b.c\r\n\r\nbody') });
            return response(200, fakeMessages[m[1]]);
          }
          if (url.indexOf('/messages?') >= 0 || url.endsWith('/messages')) return response(200, { messages: opts.history || [] });
          return response(404, { error: { message: 'not found' } });
        }
        if (url.indexOf('rdap.org') >= 0) return response(200, { events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - (opts.rdapDays || 3000) * 86400000).toISOString() }] });
        if (url.indexOf('safebrowsing') >= 0) return response(200, {});
        return response(200, '');
      }
    },
    CardService: (function mk() { const f = function () {}; return new Proxy(f, { get: () => mk(), apply: () => mk() }); })()
  };
  sandbox.__calls = calls;
  sandbox.__store = store;
  return sandbox;
}

function load(sandbox) {
  const ctx = vm.createContext(sandbox);
  assert.strictEqual(typeof ctx.URL, 'undefined', 'sandbox must not define URL');
  FILES.forEach((f) => {
    // const/let in scripts are not properties of the context; expose them like Apps Script does (shared global scope).
    const src = fs.readFileSync(path.join(__dirname, f), 'utf8').replace(/^const (\w+) =/gm, 'var $1 =');
    vm.runInContext(src, ctx, { filename: f });
  });
  return ctx;
}

function gmailMessage(id, o) {
  o = o || {};
  const headers = [
    { name: 'From', value: o.from || 'Alice <alice@example.com>' },
    { name: 'To', value: 'me@gmail.com' },
    { name: 'Subject', value: o.subject || 'Hello' },
    { name: 'Authentication-Results', value: o.auth || 'mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com' }
  ];
  return {
    id, threadId: 't' + id, labelIds: ['INBOX'], internalDate: String(Date.now()),
    payload: { mimeType: 'text/plain', headers, body: { data: b64url(o.body || 'Lunch tomorrow?') } }
  };
}

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('ok   ' + name); } catch (e) { console.error('FAIL ' + name + '\n' + e.stack); process.exitCode = 1; }
}

test('benign message scans green and never needs global URL', () => {
  const ctx = load(makeSandbox({ m1: gmailMessage('m1') }, { history: [{ id: 'old' }] }));
  const r = vm.runInContext('scanMessage("m1", false, {})', ctx);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.level, 'green', JSON.stringify(r.findings) + ' skipped=' + JSON.stringify(r.skipped));
});

test('phishing message scores red with structured findings', () => {
  const m = gmailMessage('m2', {
    from: 'PayPal <service@paypa1-secure.xyz>',
    auth: 'mx.google.com; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail header.from=paypa1-secure.xyz',
    subject: 'Urgent: verify your account immediately',
    body: 'Your account will be suspended. Verify now: http://paypa1-secure.xyz/login'
  });
  const ctx = load(makeSandbox({ m2: m }, { rdapDays: 2 }));
  const r = vm.runInContext('scanMessage("m2", false, {})', ctx);
  assert.ok(!r.error, r.error);
  assert.notStrictEqual(r.level, 'green');
  assert.ok(r.findings.length > 0 && r.findings[0].id);
});

test('failed fetch yields an error result, never a clean one', () => {
  const ctx = load(makeSandbox({}));
  const r = vm.runInContext('scanMessage("missing", false, {})', ctx);
  assert.ok(r.error);
  assert.strictEqual(r.score, undefined);
});

test('deep scan is not served from the passive cache', () => {
  const sb = makeSandbox({ m3: gmailMessage('m3') });
  const ctx = load(sb);
  const p = vm.runInContext('scanMessage("m3", false, {})', ctx);
  const d = vm.runInContext('scanMessage("m3", true, {})', ctx);
  assert.strictEqual(p.deep, false);
  assert.strictEqual(d.deep, true);
});

test('failed scans are not cached', () => {
  const sb = makeSandbox({});
  const ctx = load(sb);
  vm.runInContext('scanMessage("nope", false, {})', ctx);
  sb.UrlFetchApp.fetch; // second call must hit the network again
  const before = sb.__calls.length;
  vm.runInContext('scanMessage("nope", false, {})', ctx);
  assert.ok(sb.__calls.length > before);
});

test('passive scan only expands known shorteners', () => {
  const m = gmailMessage('m4', { body: 'see https://bit.ly/abc and https://example.org/page' });
  const sb = makeSandbox({ m4: m });
  const ctx = load(sb);
  vm.runInContext('scanMessage("m4", false, {})', ctx);
  const heads = sb.__calls.filter((c) => c.method === 'head').map((c) => c.url);
  assert.ok(heads.every((u) => u.indexOf('bit.ly') >= 0), JSON.stringify(heads));
  assert.ok(!sb.__calls.some((c) => c.url === 'https://example.org/page'));
});

test('neutralize moves thread to spam without deleting', () => {
  const sb = makeSandbox({ m5: gmailMessage('m5') });
  const ctx = load(sb);
  vm.runInContext('handleNeutralize({parameters:{messageId:"m5"}})', ctx);
  const mod = sb.__calls.find((c) => c.url.indexOf('/threads/') >= 0 && c.url.indexOf('/modify') >= 0);
  assert.ok(mod, 'thread modify call expected');
  assert.ok(mod.body.indexOf('SPAM') >= 0 && mod.body.indexOf('TRASH') < 0);
});

test('report creates a draft to APWG and sends nothing', () => {
  const sb = makeSandbox({ m6: gmailMessage('m6') });
  const ctx = load(sb);
  vm.runInContext('handleReportPhishing({parameters:{messageId:"m6"}})', ctx);
  const draft = sb.__calls.find((c) => c.url.indexOf('/drafts') >= 0);
  assert.ok(draft);
  assert.ok(!sb.__calls.some((c) => c.url.indexOf('/send') >= 0));
  const raw = JSON.parse(draft.body).message.raw;
  const mime = Buffer.from(raw.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  assert.ok(mime.indexOf('reportphishing@apwg.org') >= 0 && mime.indexOf('message/rfc822') >= 0);
});

test('trusting a sender persists and invalidates cache', () => {
  const sb = makeSandbox({ m7: gmailMessage('m7') });
  const ctx = load(sb);
  const g1 = vm.runInContext('Settings.generation()', ctx);
  vm.runInContext('handleTrustSender({parameters:{domain:"example.com"}})', ctx);
  assert.deepStrictEqual(JSON.parse(vm.runInContext('JSON.stringify(Settings.load().allowDomains)', ctx)), ['example.com']);
  assert.notStrictEqual(g1, vm.runInContext('Settings.generation()', ctx));
});

test('manifest scopes are narrow and consistent with the code', () => {
  const man = JSON.parse(fs.readFileSync(path.join(__dirname, 'appsscript.json'), 'utf8'));
  const s = man.oauthScopes;
  assert.ok(s.indexOf('https://www.googleapis.com/auth/gmail.modify') >= 0);
  assert.ok(!s.some((x) => x === 'https://mail.google.com/' || /gmail\.(send|readonly|compose)$/.test(x)));
  assert.ok(man.addOns.common.homepageTrigger);
  const code = FILES.map((f) => fs.readFileSync(path.join(__dirname, f), 'utf8')).join('\n');
  assert.ok(!/GmailApp\./.test(code), 'GmailApp would need the full mail scope');
  assert.ok(!/\bnew URL\(/.test(code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')), 'no global URL in Apps Script');
});

console.log(passed + ' passed');
