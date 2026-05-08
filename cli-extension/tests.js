import { calculateScore, isTyposquatted, analyzeLinguisticDrift } from './scoring-engine.js';

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

testLinguisticDrift();
testScoring();
