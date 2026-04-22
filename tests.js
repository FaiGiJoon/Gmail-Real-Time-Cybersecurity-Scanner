/**
 * Unit tests for the Gmail Cybersecurity Scanner.
 */

function runTests() {
  console.log('Starting tests...');

  testLinkTextMismatch();
  testSanitizeContent();
  testCalculateSecurityScore();
  testVerifySender();
  testNeutralizeLogic();

  console.log('All tests completed.');
}

function testLinkTextMismatch() {
  console.log('Testing isLinkTextMismatch...');

  const cases = [
    { text: 'https://www.google.com', url: 'https://www.google.com', expected: false },
    { text: 'Google Search', url: 'https://www.google.com', expected: false },
    { text: 'https://www.google.com', url: 'https://evil-site.ru', expected: true },
    { text: 'Visit google.com', url: 'https://evil-site.ru', expected: true },
    { text: 'mybank.com', url: 'https://mybank.com/login', expected: false },
    { text: 'paypal.com', url: 'https://pay-pal-secure.com', expected: true },
    { text: 'www.amazon.com', url: 'https://amaz0n-security.co', expected: true },
    { text: 'Check here: google.com', url: 'https://google.com/search', expected: false },
    { text: 'google.com', url: 'https://fakegoogle.com', expected: true },
    { text: 'google.com', url: 'https://mail.google.com', expected: false }
  ];

  cases.forEach(c => {
    const result = isLinkTextMismatch(c.text, c.url);
    if (result !== c.expected) {
      console.error(`FAILED: text="${c.text}", url="${c.url}". Expected ${c.expected}, got ${result}`);
    } else {
      console.log(`PASSED: text="${c.text}"`);
    }
  });
}

function testSanitizeContent() {
  console.log('Testing viewSanitizedContent logic...');

  const htmlBody = '<div>Hello</div><script>alert("xss")</script><style>.body{}</style><a href="http://evil.com">Click</a><img src="pixel.png">';
  const sanitize = (html) => html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const expected = 'Hello Click';
  if (sanitize(htmlBody) !== expected) {
    console.error(`FAILED: Sanitize Content logic mismatch.`);
  } else {
    console.log('PASSED: Sanitize Content logic');
  }
}

function testCalculateSecurityScore() {
  console.log('Testing calculateSecurityScore...');

  const secureData = {
    warnings: [],
    auth: { dmarc: 'pass', spf: 'pass', dkim: 'pass' },
    senderVerified: true,
    urls: [],
    attachmentsCount: 0
  };

  const secureScore = calculateSecurityScore(secureData);
  if (secureScore.level !== CONSTANTS.THREAT_LEVELS.GREEN) console.error('FAILED: Secure Score level');

  const dangerousData = {
    warnings: ['Malicious URL detected by Safe Browsing: http://evil.com'],
    auth: { dmarc: 'fail', spf: 'fail', dkim: 'fail' },
    senderVerified: false,
    urls: ['http://evil.com'],
    attachmentsCount: 0
  };

  const dangerousScore = calculateSecurityScore(dangerousData);
  if (dangerousScore.level !== CONSTANTS.THREAT_LEVELS.RED) console.error('FAILED: Dangerous Score level');

  console.log('PASSED: calculateSecurityScore');
}

function testVerifySender() {
  console.log('Testing verifySender...');

  const cases = [
    { header: '"Google Support" <support@google.com>', expected: true },
    { header: '"support@google.com" <scammer@evil.com>', expected: false },
    { header: 'support@google.com', expected: true },
    { header: 'Random Name <someone@else.com>', expected: true }
  ];

  cases.forEach(c => {
    const result = verifySender(c.header);
    if (result !== c.expected) {
      console.error(`FAILED: header="${c.header}". Expected ${c.expected}, got ${result}`);
    } else {
      console.log(`PASSED: header="${c.header}"`);
    }
  });
}

function testNeutralizeLogic() {
  console.log('Testing handleNeutralize logic...');

  let spamMoved = false;
  let readMarked = false;

  const mockMessage = {
    moveToSpam: () => { spamMoved = true; },
    markRead: () => { readMarked = true; }
  };

  const originalGmailApp = globalThis.GmailApp;
  globalThis.GmailApp = {
    getMessageById: () => mockMessage
  };

  handleNeutralize({parameters: {messageId: '123'}});

  if (spamMoved && readMarked) {
    console.log('PASSED: Neutralize Logic');
  } else {
    console.error(`FAILED: Neutralize Logic. spamMoved=${spamMoved}, readMarked=${readMarked}`);
  }

  globalThis.GmailApp = originalGmailApp;
}
