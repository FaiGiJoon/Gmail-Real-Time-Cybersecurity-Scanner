/**
 * background.js - Service Worker for Gmail Cybersecurity Scanner extension.
 */

// Handles OAuth token acquisition via chrome.identity
async function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, function(token) {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(token);
      }
    });
  });
}

// Listen for installation/startup events
chrome.runtime.onInstalled.addListener(() => {
  console.log("Gmail Cybersecurity Scanner Extension Installed.");
});
