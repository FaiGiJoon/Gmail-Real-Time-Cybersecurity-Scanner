/**
 * Gmail Cybersecurity Add-on Public API Gateway.
 * This file aggregates and exports the public API functions of the scanner
 * to facilitate reusability in external contexts (e.g., other scripts or libraries).
 *
 * Version: 1.2.0 - Sentinel Phase
 */

const GmailScanner = {
  /**
   * Main entry point to run a complete multi-layer security scan.
   * @param {GoogleAppsScript.Gmail.GmailMessage} message
   * @param {boolean} isDeepScan
   * @return {Object} Core security audit results.
   */
  runSecurityScan: function(message, isDeepScan) {
    return runSecurityScan(message, isDeepScan);
  },

  /**
   * Calculates security score and level from scan results.
   * @param {Object} data Security scan data.
   * @return {Object} Score details.
   */
  calculateSecurityScore: function(data) {
    return calculateSecurityScore(data);
  },

  /**
   * Builds the security Card UI.
   * @param {Object} data Security scan data.
   * @return {GoogleAppsScript.Card_Service.Card}
   */
  createSecurityCard: function(data) {
    return createSecurityCard(data);
  },

  /**
   * Primary contextual trigger to render the Add-on sidebar UI.
   * @param {Object} e Trigger event.
   * @return {GoogleAppsScript.Card_Service.Card[]}
   */
  getContextualAddOn: function(e) {
    return getContextualAddOn(e);
  }
};
