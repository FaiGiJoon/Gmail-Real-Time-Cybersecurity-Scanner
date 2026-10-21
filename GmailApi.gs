/**
 * Thin wrapper over the Gmail REST API, called with the add-on's own OAuth token.
 *
 * Why REST and not GmailApp: GmailApp requires the all-powerful https://mail.google.com/
 * scope (it can permanently delete mail). The REST API accepts the narrower
 * gmail.modify scope, which is enough to read, label, move to spam and mark read but
 * cannot delete anything permanently.
 */
const GmailApi = {
  /**
   * @param {string} method 'get' | 'post'
   * @param {string} path path after /users/me
   * @param {Object=} query
   * @param {Object=} body
   */
  call: function (method, path, query, body) {
    let url = SCANNER.GMAIL_API + path;
    if (query) {
      const parts = [];
      Object.keys(query).forEach(function (k) {
        const v = query[k];
        (Array.isArray(v) ? v : [v]).forEach(function (item) {
          if (item !== undefined && item !== null) parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(item));
        });
      });
      if (parts.length) url += '?' + parts.join('&');
    }
    const options = {
      method: method,
      headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() },
      muteHttpExceptions: true
    };
    if (body !== undefined) {
      options.contentType = 'application/json';
      options.payload = JSON.stringify(body);
    }
    let response;
    for (let attempt = 0; attempt < 2; attempt++) {
      response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      if (code !== 429 && code < 500) break;
      Utilities.sleep(400 * (attempt + 1));
    }
    const code = response.getResponseCode();
    const text = response.getContentText();
    if (code >= 400) {
      let reason = text;
      try { reason = JSON.parse(text).error.message; } catch (e) { /* keep raw text */ }
      const err = new Error('Gmail API ' + code + ': ' + String(reason).slice(0, 200));
      err.status = code;
      throw err;
    }
    return text ? JSON.parse(text) : {};
  },

  getMessage: function (id) {
    return GmailApi.call('get', '/messages/' + encodeURIComponent(id), { format: 'full' });
  },

  /** Returns the whole RFC 822 message as an array of unsigned bytes. */
  getRawBytes: function (id) {
    const res = GmailApi.call('get', '/messages/' + encodeURIComponent(id), { format: 'raw' });
    return GmailApi.toUnsigned(Utilities.base64DecodeWebSafe(res.raw));
  },

  /** Returns attachment bytes as an array of unsigned bytes. */
  getAttachmentBytes: function (messageId, attachmentId) {
    const res = GmailApi.call('get', '/messages/' + encodeURIComponent(messageId) + '/attachments/' + encodeURIComponent(attachmentId));
    return GmailApi.toUnsigned(Utilities.base64DecodeWebSafe(res.data));
  },

  toUnsigned: function (bytes) {
    const out = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] & 0xFF;
    return out;
  },

  toSigned: function (bytes) {
    const out = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] > 127 ? bytes[i] - 256 : bytes[i];
    return out;
  },

  list: function (q, maxResults) {
    const res = GmailApi.call('get', '/messages', { q: q, maxResults: maxResults || 5 });
    return res.messages || [];
  },

  modifyThread: function (threadId, addLabelIds, removeLabelIds) {
    return GmailApi.call('post', '/threads/' + encodeURIComponent(threadId) + '/modify', undefined, {
      addLabelIds: addLabelIds || [],
      removeLabelIds: removeLabelIds || []
    });
  },

  /** Finds or creates a user label and returns its id. */
  ensureLabel: function (name) {
    const labels = GmailApi.call('get', '/labels').labels || [];
    for (let i = 0; i < labels.length; i++) {
      if (labels[i].name === name) return labels[i].id;
    }
    return GmailApi.call('post', '/labels', undefined, {
      name: name,
      labelListVisibility: 'labelShow',
      messageListVisibility: 'show'
    }).id;
  },

  /** Creates a draft from RFC 822 bytes. The user reviews and sends it themselves. */
  createDraft: function (rawBytes) {
    return GmailApi.call('post', '/drafts', undefined, {
      message: { raw: Utilities.base64EncodeWebSafe(GmailApi.toSigned(rawBytes)) }
    });
  }
};
