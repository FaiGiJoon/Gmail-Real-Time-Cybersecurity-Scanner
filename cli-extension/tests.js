import { calculateScore, isTyposquatted } from './scoring-engine.js';

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

testScoring();
