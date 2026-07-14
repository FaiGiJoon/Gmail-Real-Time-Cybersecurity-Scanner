/**
 * options.js - Controller for extension settings.
 */

document.addEventListener('DOMContentLoaded', () => {
  const sbInput = document.getElementById('safe-browsing-key');
  const cvInput = document.getElementById('cloud-vision-key');
  const vtInput = document.getElementById('virustotal-key');
  const saveBtn = document.getElementById('save-btn');
  const statusEl = document.getElementById('status');

  // Load saved keys
  chrome.storage.local.get(['SAFE_BROWSING_API_KEY', 'CLOUD_VISION_API_KEY', 'VIRUSTOTAL_API_KEY'], (result) => {
    if (result.SAFE_BROWSING_API_KEY) sbInput.value = result.SAFE_BROWSING_API_KEY;
    if (result.CLOUD_VISION_API_KEY) cvInput.value = result.CLOUD_VISION_API_KEY;
    if (result.VIRUSTOTAL_API_KEY) vtInput.value = result.VIRUSTOTAL_API_KEY;
  });

  // Save keys
  saveBtn.addEventListener('click', () => {
    chrome.storage.local.set({
      SAFE_BROWSING_API_KEY: sbInput.value.trim(),
      CLOUD_VISION_API_KEY: cvInput.value.trim(),
      VIRUSTOTAL_API_KEY: vtInput.value.trim()
    }, () => {
      statusEl.textContent = 'Settings saved successfully!';
      setTimeout(() => {
        statusEl.textContent = '';
      }, 3000);
    });
  });
});
