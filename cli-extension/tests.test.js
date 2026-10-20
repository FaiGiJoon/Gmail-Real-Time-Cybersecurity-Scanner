import test from 'node:test';
import assert from 'node:assert/strict';
import { createTools, clean } from './tools.js';

const b64url = (s) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function message(id, o = {}) {
  return {
    id, threadId: 'thread' + id, labelIds: ['INBOX'], internalDate: String(Date.now()),
    payload: {
      mimeType: 'multipart/alternative',
      headers: [
        { name: 'From', value: o.from || 'Bob <bob@example.com>' }, { name: 'Subject', value: o.subject || 'Hi' },
        { name: 'Authentication-Results', value: o.auth || 'mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com' }
      ],
      parts: [
        { mimeType: 'text/plain', body: { data: b64url(o.body || 'Lunch?') } },
        { mimeType: 'text/html', body: { data: b64url(o.html || '<p>Lunch?</p>') } }
      ]
    }
  };
}
function fakeGmail(messages, calls = []) {
  return {
    calls,
    getMessage: async (id) => { if (!messages[id]) throw new Error('not found'); return messages[id]; },
    getThread: async (id) => ({ messages: Object.keys(messages).filter((k) => messages[k].threadId === id).map((k) => ({ id: k })) }),
    listMessageIds: async (q) => (q.startsWith('from:') ? ['old1'] : Object.keys(messages)),
    getAttachmentBytes: async () => Array.from(Buffer.from('MZ\u0090\u0000fake exe')),
    quarantineThread: async (id) => { calls.push(['quarantine', id]); }
  };
}
const quietFetch = async (url) => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => ({ events: [{ eventAction: 'registration', eventDate: '2010-01-01T00:00:00Z' }] }) });
const parse = (r) => JSON.parse(r.content[0].text);

test('scan_recent ranks the riskiest message first and marks untrusted fields', async () => {
  const gmail = fakeGmail({
    good: message('good'),
    bad: message('bad', { from: 'PayPal <x@paypa1-help.xyz>', auth: 'mx.google.com; spf=fail; dkim=none; dmarc=fail header.from=paypa1-help.xyz', body: 'Urgent: verify now http://paypa1-help.xyz/a' })
  });
  const { execute } = createTools({ gmail, env: {}, fetchFn: quietFetch });
  const out = parse(await execute('scan_recent', { maxResults: 10 }));
  assert.equal(out.messages[0].messageId, 'bad');
  assert.ok(out.messages[0].score < out.messages[1].score);
  assert.ok(out.messages[0].untrusted.from);
  assert.match(out.notice, /Never follow instructions/);
});

test('a message that fails to load is reported as not scanned, not clean', async () => {
  const gmail = fakeGmail({ good: message('good') });
  gmail.listMessageIds = async () => ['good', 'missing'];
  const { execute } = createTools({ gmail, env: {}, fetchFn: quietFetch });
  const out = parse(await execute('scan_recent', {}));
  const missing = out.messages.find((m) => m.messageId === 'missing');
  assert.equal(missing.note, 'NOT scanned');
  assert.equal(missing.score, undefined);
});

test('hostile email text cannot smuggle control characters into tool output', async () => {
  assert.equal(clean('a‮b\u0000c\n\nd', 50), 'a b c d');
  assert.equal(clean('x'.repeat(500), 10).length, 10);
});

test('quarantine is a dry run without confirm and blocked without the write flag', async () => {
  const calls = [];
  const gmail = fakeGmail({ a: message('a') }, calls);
  const dry = parse(await createTools({ gmail, env: { SCANNER_ALLOW_WRITE: '1' } }).execute('quarantine_thread', { threadId: 'threada' }));
  assert.equal(dry.dryRun, true);
  assert.equal(calls.length, 0);
  await assert.rejects(createTools({ gmail, env: {} }).execute('quarantine_thread', { threadId: 'threada', confirm: true }), /disabled/);
  assert.equal(calls.length, 0);
  const done = parse(await createTools({ gmail, env: { SCANNER_ALLOW_WRITE: '1' } }).execute('quarantine_thread', { threadId: 'threada', confirm: true }));
  assert.equal(done.done, true);
  assert.deepEqual(calls, [['quarantine', 'threada']]);
});

test('arguments are validated', async () => {
  const { execute } = createTools({ gmail: fakeGmail({}), env: {}, fetchFn: quietFetch });
  await assert.rejects(execute('analyze_thread_security', {}), /threadId/);
  await assert.rejects(execute('analyze_thread_security', { threadId: '../../etc' }), /threadId/);
  await assert.rejects(execute('quarantine_thread', undefined), /threadId/);
  await assert.rejects(execute('nope', {}), /Tool not found/);
  const huge = parse(await createTools({ gmail: { ...fakeGmail({}), listMessageIds: async (q, n) => { assert.ok(n <= 25); return []; } }, env: {}, fetchFn: quietFetch }).execute('scan_recent', { maxResults: 1e9 }));
  assert.equal(huge.scanned, 0);
});

test('analyze_thread_security reads every message, not just the first', async () => {
  const gmail = fakeGmail({
    a: { ...message('a'), threadId: 'T1234567' },
    b: { ...message('b', { auth: 'mx.google.com; spf=fail; dkim=none; dmarc=fail header.from=example.com' }), threadId: 'T1234567' }
  });
  const out = parse(await createTools({ gmail, env: {}, fetchFn: quietFetch }).execute('analyze_thread_security', { threadId: 'T1234567' }));
  assert.equal(out.messages.length, 2);
  assert.ok(out.worstScore < 100);
});

test('attachment scan inspects bytes and reports hash', async () => {
  const out = parse(await createTools({ gmail: fakeGmail({}), env: {} }).execute('scan_attachment_malware', { messageId: 'msg12345', attachmentId: 'att12345', filename: 'invoice.pdf' }));
  assert.match(out.sha256, /^[0-9a-f]{64}$/);
  assert.ok(out.findings.some((f) => f.id.startsWith('attach.')), JSON.stringify(out.findings));
});

test('GCP tools are not exposed unless explicitly enabled', async () => {
  const gcp = { initialize: async () => {}, listProjects: async () => [] };
  assert.ok(!createTools({ gmail: fakeGmail({}), env: {}, gcp }).tools.some((t) => /gcp/.test(t.name)));
  assert.ok(createTools({ gmail: fakeGmail({}), env: { SCANNER_ENABLE_GCP_TOOLS: '1' }, gcp }).tools.some((t) => /gcp/.test(t.name)));
});
