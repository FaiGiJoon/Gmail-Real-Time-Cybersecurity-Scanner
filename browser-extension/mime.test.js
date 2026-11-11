const test = require('node:test');
const assert = require('node:assert');
const Mime = require('./mime.js');
const { createEngine } = require('./engine.js');

const CRLF = (s) => s.replace(/\n/g, '\r\n');
const AUTH_PASS = 'mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com';

function raw(o = {}) {
  return CRLF([
    'Authentication-Results: ' + (o.auth || AUTH_PASS),
    'From: ' + (o.from || 'Bob <bob@example.com>'),
    'To: me@example.org',
    'Subject: ' + (o.subject || 'Lunch'),
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="XYZ"',
    '',
    '--XYZ',
    'Content-Type: multipart/alternative; boundary=ALT',
    '',
    '--ALT',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    o.body || 'Caf=C3=A9 at noon?',
    '--ALT',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(o.html || '<p>Café at noon?</p>').toString('base64'),
    '--ALT--',
    ...(o.attach ? [
      '--XYZ',
      'Content-Type: application/octet-stream; name="' + o.attach.name + '"',
      'Content-Disposition: attachment;',
      ' filename="' + o.attach.name + '"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from(o.attach.bytes).toString('base64').replace(/(.{76})/g, '$1\n')
    ] : []),
    '--XYZ--',
    ''
  ].join('\n'));
}

const env = (o = {}) => ({
  fetch: async (url) => ({ ok: true, status: 200, json: async () => (url.includes('rdap') ? { events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - (o.rdapDays || 4000) * 864e5).toISOString() }] } : {}) }),
  getSettings: async () => ({ keys: {}, config: {} })
});

test('parses nested multipart, QP and base64 into Gmail API shape', () => {
  const m = Mime.toGmailApiMessage(raw(), { id: 'msg-f:1', threadId: 't' });
  assert.strictEqual(m.id, 'msg-f:1');
  assert.strictEqual(m.payload.mimeType, 'multipart/mixed');
  const alt = m.payload.parts[0];
  assert.strictEqual(alt.parts.length, 2);
  assert.strictEqual(Buffer.from(alt.parts[0].body.data, 'base64').toString('utf8'), 'Café at noon?');
  assert.ok(m.payload.headers.some((h) => h.name === 'Authentication-Results'));
});

test('folded headers and RFC 2231 filenames are read', () => {
  const h = Mime.parseHeaders('Subject: a\r\n  b\r\nX: 1');
  assert.deepStrictEqual(h, [{ name: 'Subject', value: 'a b' }, { name: 'X', value: '1' }]);
  assert.strictEqual(Mime.param("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf", 'filename'), 'résumé.pdf');
});

test('benign raw message scans green without any OAuth token', async () => {
  const r = await createEngine(env()).scanRaw(raw(), { id: 'msg-f:1' });
  assert.strictEqual(r.level, 'green', JSON.stringify(r.findings));
  assert.strictEqual(r.subject, 'Lunch');
  assert.ok(r.skipped.includes('First-time sender check'), 'sender history must be listed as not checked');
});

test('spoofed raw message with an executable attachment is red', async () => {
  const r = await createEngine(env({ rdapDays: 2 })).scanRaw(raw({
    from: 'PayPal Support <help@paypa1-secure.xyz>',
    auth: 'mx.google.com; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail header.from=paypa1-secure.xyz',
    body: 'Your account is suspended. Verify immediately: http://paypa1-secure.xyz/login',
    attach: { name: 'invoice.pdf.exe', bytes: [0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0] }
  }), { id: 'msg-f:2' });
  assert.strictEqual(r.level, 'red');
  assert.strictEqual(r.attachmentsCount, 1);
  assert.ok(r.findings.some((f) => /dmarc/i.test(f.id)));
});

test('large attachments are truncated but keep their real size', () => {
  const big = new Array(200000).fill(65);
  const m = Mime.toGmailApiMessage(raw({ attach: { name: 'a.bin', bytes: big } }), {});
  const att = m.payload.parts[1];
  assert.ok(att.body.data.length <= 12000);
  assert.ok(Math.abs(att.body.size - 200000) < 4);
});

test('garbage input is rejected instead of scanning as clean', () => {
  assert.throws(() => Mime.toGmailApiMessage('<html>login page</html>', {}), /email source/);
});
