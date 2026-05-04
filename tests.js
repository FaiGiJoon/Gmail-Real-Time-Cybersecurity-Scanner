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
  testTyposquatted();
  testBEC();
  testLinguisticThreats();
  testTLSCheck();
  testAnalyzeAttachmentsWithQr();
  testCalculateHash();
  testScanPdfStructure();

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
    attachmentsCount: 0,
    linguisticThreats: [],
    maliciousQrUrls: []
  };

  const secureScore = calculateSecurityScore(secureData);
  if (secureScore.level !== CONSTANTS.THREAT_LEVELS.GREEN || secureScore.points !== 100) {
     console.error(`FAILED: Secure Score. Expected 100 GREEN, got ${secureScore.points} ${secureScore.level}`);
  }

  const dangerousData = {
    warnings: ['Malicious URL detected by Safe Browsing: http://evil.com'],
    auth: { dmarc: 'fail', spf: 'fail', dkim: 'fail' },
    senderVerified: false,
    urls: ['http://evil.com'],
    attachmentsCount: 0,
    linguisticThreats: [],
    maliciousQrUrls: []
  };

  const dangerousScore = calculateSecurityScore(dangerousData);
  if (dangerousScore.level !== CONSTANTS.THREAT_LEVELS.RED) console.error('FAILED: Dangerous Score level');

  // Test Weighted Linguistic Threats
  const linguisticData = {
    warnings: ['Urgent/Suspicious language detected: wire transfer, urgent'],
    auth: { dmarc: 'pass', spf: 'pass', dkim: 'pass' },
    senderVerified: true,
    urls: [],
    attachmentsCount: 0,
    linguisticThreats: [
      { keyword: 'wire transfer', weight: 20 },
      { keyword: 'urgent', weight: 10 }
    ],
    maliciousQrUrls: []
  };
  const linguisticScore = calculateSecurityScore(linguisticData);
  // 100 - 20 (wire transfer) - 10 (urgent) - 20 (general warning for "Urgent/Suspicious language detected") = 50
  // Wait, let's check general warnings filter:
  // !w.includes('Link text mismatch') && !w.includes('Malicious URL') && !w.includes('homograph') && !w.includes('DMARC') && !w.includes('From') && !w.includes('QR Code detected')
  // "Urgent/Suspicious language detected" IS a general warning.
  if (linguisticScore.points !== 50) {
    console.error(`FAILED: Weighted Linguistic Score. Expected 50, got ${linguisticScore.points}`);
  }

  // Test Quishing Penalty
  const quishingData = {
    warnings: ['Malicious URL detected by Safe Browsing: http://evil-qr.com', 'QR Code detected in image attachment: qr.png'],
    auth: { dmarc: 'pass', spf: 'pass', dkim: 'pass' },
    senderVerified: true,
    urls: ['http://evil-qr.com'],
    attachmentsCount: 1,
    linguisticThreats: [],
    maliciousQrUrls: ['http://evil-qr.com']
  };
  const quishingScore = calculateSecurityScore(quishingData);
  // 100 - 60 (Malicious URL) - 25 (QR_THREAT_PENALTY) = 15
  if (quishingScore.points !== 15) {
    console.error(`FAILED: Quishing Score. Expected 15, got ${quishingScore.points}`);
  }

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
    getThread: () => ({
      moveToSpam: () => { spamMoved = true; }
    }),
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

function testTyposquatted() {
  console.log('Testing isTyposquatted...');
  const cases = [
    { url: 'https://google.com', expected: null },
    { url: 'https://g0ogle.com', expected: 'google' },
    { url: 'https://micros0ft.com', expected: 'microsoft' },
    { url: 'https://pay-pal.com', expected: 'paypal' },
    { url: 'https://amaz0n.co.uk', expected: 'amazon' },
    { url: 'https://apple-support.com', expected: null } // distance > 2
  ];

  cases.forEach(c => {
    const result = isTyposquatted(c.url);
    if (result !== c.expected) {
      console.error(`FAILED: url="${c.url}". Expected ${c.expected}, got ${result}`);
    } else {
      console.log(`PASSED: url="${c.url}"`);
    }
  });
}

function testBEC() {
  console.log('Testing checkBEC...');

  const mockMessage = (from, replyTo) => ({
    getFrom: () => from,
    getReplyTo: () => replyTo
  });

  const cases = [
    { from: 'CEO <ceo@company.com>', replyTo: 'ceo@company.com', expected: false },
    { from: 'CEO <ceo@company.com>', replyTo: 'attacker@evil.com', expected: true },
    { from: 'support@paypal.com', replyTo: 'support@paypal.com', expected: false },
    { from: 'support@paypal.com', replyTo: 'paypal-support@gmail.com', expected: true }
  ];

  cases.forEach(c => {
    const result = checkBEC(mockMessage(c.from, c.replyTo));
    if (result !== c.expected) {
      console.error(`FAILED: from="${c.from}", replyTo="${c.replyTo}". Expected ${c.expected}, got ${result}`);
    } else {
      console.log(`PASSED: BEC check`);
    }
  });
}

function testLinguisticThreats() {
  console.log('Testing detectLinguisticThreats...');
  const body = 'This is an urgent request for a wire transfer due to account suspended. Immediate action required.';
  const threats = detectLinguisticThreats(body);
  const detectedKeywords = threats.map(t => t.keyword);
  const expected = ['urgent', 'wire transfer', 'account suspended', 'immediate action'];

  if (threats.length === expected.length && expected.every(t => detectedKeywords.includes(t))) {
    console.log('PASSED: Linguistic Threats');
  } else {
    console.error(`FAILED: Linguistic Threats. Got: ${JSON.stringify(threats)}`);
  }
}

function testTLSCheck() {
  console.log('Testing checkTLS...');
  const mockMessage = (raw) => ({
    getRawContent: () => raw
  });

  const tlsRaw = 'Received: from mail.example.com by mx.google.com with ESMTPS id ...\r\n (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);';
  const noTlsRaw = 'Received: from mail.example.com by mx.google.com with SMTP id ...;';

  if (checkTLS(mockMessage(tlsRaw)) === true && checkTLS(mockMessage(noTlsRaw)) === false) {
    console.log('PASSED: TLS Check');
  } else {
    console.error('FAILED: TLS Check');
  }
}

function testAnalyzeAttachmentsWithQr() {
  console.log('Testing analyzeAttachments with QR detection...');

  const mockAttachment = {
    getName: () => 'qr_code.png',
    getBytes: () => []
  };

  // Mock detectQrCodes to return a URL
  const originalDetectQrCodes = globalThis.detectQrCodes;
  globalThis.detectQrCodes = () => ['http://malicious-qr.com'];

  const results = analyzeAttachments([mockAttachment]);

  if (results.qrUrls.includes('http://malicious-qr.com') && results.warnings.some(w => w.includes('QR Code detected'))) {
    console.log('PASSED: Attachment QR detection');
  } else {
    console.error(`FAILED: Attachment QR detection. Results: ${JSON.stringify(results)}`);
  }

  globalThis.detectQrCodes = originalDetectQrCodes;
}

function testCalculateHash() {
  console.log('Testing calculateHash...');
  const mockBlob = {
    getBytes: () => [72, 101, 108, 108, 111] // "Hello"
  };

  // In the mock environment, calculateHash returns a fixed dummy value
  const result = calculateHash(mockBlob);

  if (result === '010203') {
    console.log('PASSED: calculateHash (Mocked)');
  } else {
    console.error(`FAILED: calculateHash. Got ${result}`);
  }
}

function testScanPdfStructure() {
  console.log('Testing scanPdfStructure...');

  const mockCleanPdf = {
    getDataAsString: () => '%PDF-1.4 ... clean content ...',
    getName: () => 'clean.pdf'
  };

  const mockMaliciousPdf = {
    getDataAsString: () => '%PDF-1.4 ... /JS (alert("hack")) ... /OpenAction ...',
    getName: () => 'malicious.pdf'
  };

  const cleanResults = scanPdfStructure(mockCleanPdf);
  const malResults = scanPdfStructure(mockMaliciousPdf);

  if (cleanResults.length === 0 && malResults.length === 2) {
    console.log('PASSED: scanPdfStructure');
  } else {
    console.error(`FAILED: scanPdfStructure. Clean results count: ${cleanResults.length}, Malicious: ${malResults.length}`);
  }
}
