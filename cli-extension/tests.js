import { calculateScore, isTyposquatted, analyzeLinguisticDrift, auditSenderAlignment } from './scoring-engine.js';

function testAuditSenderAlignmentCLI() {
  console.log('Testing auditSenderAlignment in CLI extension...');
  const header = '"Daniel Ek" <daniel@evil.com>';
  const alignment = auditSenderAlignment(header);

  if (alignment.isSpoofed && alignment.penaltyWeight === 30) {
    console.log('PASSED: auditSenderAlignment CLI');
  } else {
    console.error('FAILED: auditSenderAlignment CLI', alignment);
  }
}

function testIsTyposquattedCLI() {
  console.log('Testing isTyposquatted multi-part SLD in CLI extension...');
  const url = 'https://amaz0n.co.uk';
  const result = isTyposquatted(url);
  if (result === 'amazon') {
    console.log('PASSED: isTyposquatted CLI');
  } else {
    console.error('FAILED: isTyposquatted CLI. Got: ' + result);
  }
}

function testLinguisticDrift() {
  console.log('Testing Linguistic Drift Analysis...');
  const text = "URGENT: Immediate action required. Unauthorized access detected.";
  const result = analyzeLinguisticDrift(text);
  if (result.threatDetected && result.scorePenalty === 15) {
    console.log('PASSED: Linguistic Drift');
  } else {
    console.error('FAILED: Linguistic Drift', result);
  }
}

function testScoring() {
  console.log('Testing CLI Scoring Engine...');

  const cases = [
    {
      name: 'Safe Email',
      data: { body: 'Hello world', authStatus: { dmarc: 'pass' }, senderVerified: true, warnings: [] },
      expected: 100
    },
    {
      name: 'High Risk (Urgent + Wire Transfer)',
      data: { body: 'URGENT: Please do a wire transfer', authStatus: { dmarc: 'pass' }, senderVerified: true, warnings: [] },
      expected: 70
    }
  ];

  cases.forEach(c => {
    const score = calculateScore(c.data);
    if (score === c.expected) {
      console.log(`PASSED: ${c.name}`);
    } else {
      console.error(`FAILED: ${c.name}. Expected ${c.expected}, got ${score}`);
    }
  });
}

testAuditSenderAlignmentCLI();
testIsTyposquattedCLI();
testLinguisticDrift();
testScoring();
