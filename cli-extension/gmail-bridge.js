import { google } from 'googleapis';

/**
 * Gmail I/O for the CLI/MCP server. Only the calls the scanner needs; nothing here can delete mail
 * or send mail. Requires the gmail.modify scope (read + label + spam, no permanent delete).
 */
export class GmailBridge {
  constructor() {
    this.gmail = null;
  }

  async initialize() {
    if (this.gmail) return;
    const { GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN } = process.env;
    if (!GMAIL_CLIENT_ID || !GMAIL_CLIENT_SECRET || !GMAIL_REFRESH_TOKEN) {
      throw new Error('Missing GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET or GMAIL_REFRESH_TOKEN. See cli-extension/README.md.');
    }
    const oauth2Client = new google.auth.OAuth2(GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, process.env.GMAIL_REDIRECT_URI);
    oauth2Client.setCredentials({ refresh_token: GMAIL_REFRESH_TOKEN });
    this.gmail = google.gmail({ version: 'v1', auth: oauth2Client });
  }

  async getMessage(id) {
    const res = await this.gmail.users.messages.get({ userId: 'me', id, format: 'full' });
    return res.data;
  }

  async getThread(id) {
    const res = await this.gmail.users.threads.get({ userId: 'me', id, format: 'minimal' });
    return res.data;
  }

  async listMessageIds(q, maxResults) {
    const res = await this.gmail.users.messages.list({ userId: 'me', q, maxResults });
    return (res.data.messages || []).map((m) => m.id);
  }

  /** @returns {Promise<number[]>} attachment bytes (unsigned) */
  async getAttachmentBytes(messageId, attachmentId) {
    const res = await this.gmail.users.messages.attachments.get({ userId: 'me', messageId, id: attachmentId });
    return Array.from(Buffer.from(res.data.data.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  }

  async quarantineThread(threadId, labelName = 'Security Review') {
    const labels = (await this.gmail.users.labels.list({ userId: 'me' })).data.labels || [];
    let label = labels.find((l) => l.name === labelName);
    if (!label) label = (await this.gmail.users.labels.create({ userId: 'me', requestBody: { name: labelName } })).data;
    await this.gmail.users.threads.modify({
      userId: 'me',
      id: threadId,
      requestBody: { addLabelIds: [label.id, 'SPAM'], removeLabelIds: ['INBOX', 'UNREAD'] }
    });
  }
}
