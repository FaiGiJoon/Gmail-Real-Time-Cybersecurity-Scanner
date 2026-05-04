import { google } from 'googleapis';

export class GmailBridge {
  constructor() {
    this.auth = null;
    this.gmail = null;
  }

  async initialize() {
    const oauth2Client = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      process.env.GMAIL_REDIRECT_URI
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.GMAIL_REFRESH_TOKEN
    });

    this.auth = oauth2Client;
    this.gmail = google.gmail({ version: 'v1', auth: this.auth });
  }

  async listHighRiskThreads(maxResults = 10) {
    const res = await this.gmail.users.threads.list({
      userId: 'me',
      maxResults: maxResults,
      q: 'has:attachment OR "urgent" OR "wire transfer" OR "account suspended"'
    });
    return res.data.threads || [];
  }

  async getThreadDetails(threadId) {
    const res = await this.gmail.users.threads.get({
      userId: 'me',
      id: threadId
    });
    return res.data;
  }

  async quarantineThread(threadId, labelName = 'Security Review') {
    let labelId;
    const labelsRes = await this.gmail.users.labels.list({ userId: 'me' });
    const label = labelsRes.data.labels.find(l => l.name === labelName);

    if (label) {
      labelId = label.id;
    } else {
      const createRes = await this.gmail.users.labels.create({
        userId: 'me',
        requestBody: { name: labelName }
      });
      labelId = createRes.data.id;
    }

    await this.gmail.users.threads.modify({
      userId: 'me',
      id: threadId,
      requestBody: {
        addLabelIds: [labelId, 'SPAM'],
        removeLabelIds: ['INBOX']
      }
    });
  }

  async getAttachment(messageId, attachmentId) {
    const res = await this.gmail.users.messages.attachments.get({
      userId: 'me',
      messageId: messageId,
      id: attachmentId
    });
    return res.data;
  }
}
