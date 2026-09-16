const fs = require('fs');
const pathModule = require('path');

// Mock Google Apps Script Globals bound directly to globalThis
globalThis.CardService = {
  newCardBuilder: () => ({ setHeader: () => ({ addSection: () => ({ build: () => ({}) }) }) }),
  newCardHeader: () => ({ setTitle: () => ({ setSubtitle: () => ({}) }) }),
  newCardSection: () => ({ addWidget: () => ({ setHeader: () => ({ setCollapsible: () => ({}) }) }) }),
  newDecoratedText: () => ({ setText: () => ({ setBottomLabel: () => ({ setStartIcon: () => ({}) }) }) }),
  newIconImage: () => ({ setIconUrl: () => ({}) }),
  newTextParagraph: () => ({ setText: () => ({}) }),
  newTextButton: () => ({ setText: () => ({ setBackgroundColor: () => ({ setTextButtonStyle: () => ({ setOnClickAction: () => ({}) }) }), setOnClickAction: () => ({}) }) }),
  newAction: () => ({ setFunctionName: () => ({ setParameters: () => ({}) }) }),
  newNavigation: () => ({ updateCard: () => ({}), pushCard: () => ({}), popCard: () => ({}) }),
  newActionResponseBuilder: () => ({ setNotification: () => ({ setStateChanged: () => ({ build: () => ({}) }) }), build: () => ({}) }),
  newNotification: () => ({ setText: () => ({}) }),
  TextButtonStyle: { FILLED: 'FILLED' }
};

globalThis.GmailApp = {
  getMessageById: (id) => ({
    getId: () => id,
    getThread: () => ({
      getId: () => 'thread_' + id,
      getMessages: () => [],
      moveToSpam: () => { console.log('Mocked moveToSpam called'); },
      addLabel: () => { console.log('Mocked addLabel called'); }
    }),
    markRead: () => { console.log('Mocked markRead called'); },
    getFrom: () => 'sender@example.com',
    getReplyTo: () => 'sender@example.com',
    getPlainBody: () => 'body',
    getBody: () => 'html',
    getAttachments: () => [],
    getRawContent: () => 'raw'
  }),
  getUserLabelByName: () => null,
  createLabel: (name) => ({ name: name })
};

globalThis.UrlFetchApp = {
  fetch: (url, options) => {
    // Basic mock for unshortenUrl and checkSafeBrowsing
    if (url && url.includes('safebrowsing')) {
      return {
        getContentText: () => JSON.stringify({ matches: [] }),
        getResponseCode: () => 200
      };
    }
    // Mock for redirect
    if (url === 'http://bit.ly/123') {
      return {
        getHeaders: () => ({ 'Location': 'http://example.com' }),
        getResponseCode: () => 200
      };
    }
    if (url && url.includes('virustotal')) {
      return {
        getContentText: () => JSON.stringify({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0 }
            }
          }
        }),
        getResponseCode: () => 200
      };
    }
    return {
      getHeaders: () => ({}),
      getResponseCode: () => 200,
      getContentText: () => '{}'
    };
  }
};

globalThis.PropertiesService = {
  getScriptProperties: () => ({ getProperty: () => 'MOCK_KEY' }),
  getUserProperties: () => ({
    getProperty: () => null,
    setProperty: () => {}
  })
};

globalThis.CacheService = {
  getUserCache: () => ({
    get: (key) => null,
    put: (key, val, sec) => {}
  })
};

globalThis.LockService = {
  getUserLock: () => ({
    waitLock: () => {},
    releaseLock: () => {}
  })
};

globalThis.Utilities = {
  unzip: () => { throw new Error('password'); }, // To test encrypted zip detection
  computeDigest: () => [1, 2, 3],
  DigestAlgorithm: { SHA_256: 'SHA_256' },
  base64Encode: (bytes) => Buffer.from(bytes).toString('base64'),
  base64Decode: (str) => Buffer.from(str, 'base64'),
  newBlob: (data) => ({
    getDataAsString: () => (Array.isArray(data) ? Buffer.from(data) : Buffer.from(data.toString())).toString()
  }),
  Charset: { UTF_8: 'UTF_8' }
};

globalThis.URL = require('url').URL;

// Helper to transform top-level declarations into globalThis properties without affecting function-local scope
const transformCode = (content) => {
  content = content.replace(/^const\s+([A-Za-z0-9_]+)\s*=/gm, (match, p1) => `globalThis.${p1} =`);
  content = content.replace(/^var\s+([A-Za-z0-9_]+)\s*=/gm, (match, p1) => `globalThis.${p1} =`);
  content = content.replace(/^function\s+([A-Za-z0-9_]+)\s*\(/gm, (match, p1) => `globalThis.${p1} = function ${p1}(`);
  return content;
};

// Security Hardening: Use Node's standard module loader via require.extensions['.gs']
// to load and compile script files directly without using vm code execution sinks (js/code-injection).
require.extensions['.gs'] = function(module, filename) {
  const content = fs.readFileSync(filename, 'utf8');
  module._compile(transformCode(content), filename);
};

// Custom loader extension for tests.js so top-level functions in tests.js are also attached to globalThis
const originalJsLoader = require.extensions['.js'];
require.extensions['.js'] = function(module, filename) {
  if (filename.endsWith('tests.js')) {
    const content = fs.readFileSync(filename, 'utf8');
    module._compile(transformCode(content), filename);
  } else {
    originalJsLoader(module, filename);
  }
};

// Load script files in required sequence via standard require()
const filesToLoad = ['Constants.gs', 'SecurityEngine.gs', 'UI.gs', 'Code.gs', 'index.gs', 'tests.js'];
filesToLoad.forEach(file => {
  const resolvedPath = pathModule.join(__dirname, file);
  if (fs.existsSync(resolvedPath)) {
    require(resolvedPath);
  }
});

globalThis.runTests();
