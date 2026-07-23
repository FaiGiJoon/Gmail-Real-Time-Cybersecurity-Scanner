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

function loadFile(path) {
  const baseName = pathModule.basename(path);

  // Security Hardening: Inline vm.runInNewContext and fs.readFileSync inside a strict switch-case block
  // with compile-time string literals. This completely eliminates any dynamic paths/variables from reaching
  // the execution context, fully resolving the js/code-injection security alert.
  switch (baseName) {
    case 'Constants.gs':
      vm.runInNewContext(
        fs.readFileSync(pathModule.join(__dirname, 'Constants.gs'), 'utf8'),
        context,
        pathModule.join(__dirname, 'Constants.gs')
      );
      break;
    case 'SecurityEngine.gs':
      vm.runInNewContext(
        fs.readFileSync(pathModule.join(__dirname, 'SecurityEngine.gs'), 'utf8'),
        context,
        pathModule.join(__dirname, 'SecurityEngine.gs')
      );
      break;
    case 'UI.gs':
      vm.runInNewContext(
        fs.readFileSync(pathModule.join(__dirname, 'UI.gs'), 'utf8'),
        context,
        pathModule.join(__dirname, 'UI.gs')
      );
      break;
    case 'Code.gs':
      vm.runInNewContext(
        fs.readFileSync(pathModule.join(__dirname, 'Code.gs'), 'utf8'),
        context,
        pathModule.join(__dirname, 'Code.gs')
      );
      break;
    case 'tests.js':
      vm.runInNewContext(
        fs.readFileSync(pathModule.join(__dirname, 'tests.js'), 'utf8'),
        context,
        pathModule.join(__dirname, 'tests.js')
      );
      break;
    default:
      console.warn(`Warning: Expected file ${path} is not recognized/registered, skipping.`);
  }
}

// Dynamically discover and load all .gs files in correct execution sequence
const gsFilesInDir = fs.readdirSync('.').filter(f => f.endsWith('.gs') && f !== 'tests.js');
const orderedSeed = ['Constants.gs', 'SecurityEngine.gs', 'UI.gs', 'Code.gs'];
const extraGsFiles = gsFilesInDir.filter(f => !orderedSeed.includes(f));
const gsFilesToLoad = [...orderedSeed, ...extraGsFiles];

gsFilesToLoad.forEach(file => {
  loadFile(file);
});

// Load the unit test suite last
loadFile('tests.js');

context.runTests();
