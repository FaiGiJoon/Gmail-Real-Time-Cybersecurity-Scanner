/**
 * popup.js - UI Controller for Gmail Cybersecurity Scanner extension popup.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const scoreEl = document.getElementById('security-score');
  const statusEl = document.getElementById('status-text');
  const warningListEl = document.getElementById('warning-list');
  const deepScanBtn = document.getElementById('btn-deep-scan');
  const neutralizeBtn = document.getElementById('btn-neutralize');

  // Placeholder actions
  deepScanBtn.addEventListener('click', () => {
    alert('Deep scan initiated.');
  });

  neutralizeBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to move this thread to Spam and mark it as read?')) {
      alert('Thread neutralized.');
    }
  });

  // Mock initial load state
  scoreEl.textContent = '100';
  statusEl.textContent = 'Secure';
  warningListEl.innerHTML = '<li>No active threats detected.</li>';
});
