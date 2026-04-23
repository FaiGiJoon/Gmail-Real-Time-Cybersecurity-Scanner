# Gmail Real-Time Cybersecurity Scanner

## Project Description
The Gmail Real-Time Cybersecurity Scanner is a Google Apps Script (GAS) based security agent designed to protect users from sophisticated email-based threats. By leveraging the Gmail API and Google Safe Browsing API, the scanner performs deep content analysis, recursive URL unshortening, and behavioral analysis of incoming messages. The system provides an automated security score and real-time mitigation tools directly within the Gmail interface, ensuring a proactive defense against evolving cybercrime vectors.

## Key Features and Threat Mapping
The scanner's capabilities are mapped to the following critical cybercrime categories:

*   **Phishing:** Passive and deep URL scanning against global threat databases.
*   **Spear-Phishing:** Identification of link text mismatches and homograph attacks targeting specific users.
*   **Whaling:** Verification of high-profile sender display names against actual email addresses.
*   **Business Email Compromise (BEC):** Detection of "Reply-To" domain mismatches and organizational inconsistencies.
*   **Malware/Ransomware Delivery:** Static analysis of high-risk file extensions and detection of encrypted archives.
*   **Quishing (QR Phishing):** Detection of suspicious embedded images and link-heavy HTML structures.
*   **Account Hijacking:** Real-time monitoring of sensitive email headers and authentication results (SPF, DKIM, DMARC).
*   **Identity Theft:** Flagging of linguistic patterns requesting personally identifiable information (PII).
*   **Forwarding/Filter Rules Attacks:** Header analysis to detect unauthorized message routing (passive monitoring).
*   **Third-Party OAuth Scams:** Verification of "Authentication-Results" to ensure sender legitimacy.
*   **Callback Phishing:** Detection of high-pressure language and urgent "call-to-action" keywords.
*   **AI-Powered Phishing:** Advanced linguistic analysis to identify synthetic or anomalous professional requests.

## Installation Guide

### Prerequisites
*   A Google account with Gmail enabled.
*   Access to the Google Cloud Console (GCP).

### Setup Instructions
1.  **Clone the Repository:**
    Download the project files (`Code.gs`, `Constants.gs`, `SecurityUtils.gs`, `UI.gs`, `appsscript.json`) to your local environment.
2.  **Create a New Apps Script Project:**
    Visit [script.google.com](https://script.google.com) and create a new project.
3.  **Deploy Files:**
    Copy the contents of the downloaded `.gs` and `.json` files into the Apps Script editor. Ensure `appsscript.json` is correctly configured with the required OAuth scopes.
4.  **GCP Configuration:**
    - Create a new project in the [Google Cloud Console](https://console.cloud.google.com/).
    - Enable the **Safe Browsing API**.
    - Generate an **API Key** for the Safe Browsing API.
5.  **Configure Script Properties:**
    In the Apps Script project settings, add a Script Property:
    - **Property Name:** `SAFE_BROWSING_API_KEY`
    - **Value:** [Your GCP API Key]
6.  **OAuth 2.0 Authentication Flow:**
    Upon the first execution (e.g., opening an email with the add-on active), Google will prompt for authorization. The script requests the following scopes:
    - `https://www.googleapis.com/auth/gmail.addons.execute`
    - `https://www.googleapis.com/auth/gmail.readonly`
    - `https://www.googleapis.com/auth/script.external_request`
    Review and approve the permissions to enable the scanner.

## Usage Instructions
Once installed, the scanner operates as a Gmail Add-on.
1.  Open any email in your Gmail inbox.
2.  The **Cybersecurity Scanner** sidebar will automatically render a security card.
3.  **Interpret Security Logs:**
    - **Green (Secure):** No immediate threats detected.
    - **Yellow (Caution):** Minor issues found (e.g., unencrypted transmission, missing DMARC).
    - **Red (High Risk):** Critical threats detected (e.g., Malicious URL, BEC attempt).
4.  **Mitigation Actions:**
    - **Neutralize Threat:** Moves the message to Spam and marks it as read.
    - **Quarantine:** Moves the message to a "Security Review" label and removes it from the inbox.
    - **Deep Scan:** Recursively unshortens all URLs and evaluates every hop in the redirect chain.
    - **View Sanitized Content:** Displays a plain-text version of the email with all scripts and HTML stripped.
