const fs = require('fs');
const vm = require('vm');
const pathModule = require('path');

// Mock Google Apps Script Globals
const mockCardService = {
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

const mockGmailApp = {
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

const mockUrlFetchApp = {
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

const mockPropertiesService = {
  getScriptProperties: () => ({ getProperty: () => 'MOCK_KEY' }),
  getUserProperties: () => ({
    getProperty: () => null,
    setProperty: () => {}
  })
};

const mockCacheService = {
  getUserCache: () => ({
    get: (key) => null,
    put: (key, val, sec) => {}
  })
};

const mockLockService = {
  getUserLock: () => ({
    waitLock: () => {},
    releaseLock: () => {}
  })
};

const mockUtilities = {
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

const context = {
  CardService: mockCardService,
  UrlFetchApp: mockUrlFetchApp,
  PropertiesService: mockPropertiesService,
  CacheService: mockCacheService,
  LockService: mockLockService,
  Utilities: mockUtilities,
  GmailApp: mockGmailApp,
  console: console,
  URL: require('url').URL,
  globalThis: {}
};
context.globalThis = context;

// Security Hardening: Direct, sequential load calls with compile-time string literals
// to avoid any dynamic file scanning/variables in fs.readFileSync or vm.runInNewContext.
// This completely resolves CodeQL Code Injection alerts (js/code-injection).

const codeConstants = fs.readFileSync('Constants.gs', 'utf8');
vm.runInNewContext(codeConstants, context, 'Constants.gs');

const codeSecurityEngine = fs.readFileSync('SecurityEngine.gs', 'utf8');
vm.runInNewContext(codeSecurityEngine, context, 'SecurityEngine.gs');

const codeUI = fs.readFileSync('UI.gs', 'utf8');
vm.runInNewContext(codeUI, context, 'UI.gs');

const codeCode = fs.readFileSync('Code.gs', 'utf8');
vm.runInNewContext(codeCode, context, 'Code.gs');

const codeIndex = fs.readFileSync('index.gs', 'utf8');
vm.runInNewContext(codeIndex, context, 'index.gs');

const codeTests = fs.readFileSync('tests.js', 'utf8');
vm.runInNewContext(codeTests, context, 'tests.js');

context.runTests();
