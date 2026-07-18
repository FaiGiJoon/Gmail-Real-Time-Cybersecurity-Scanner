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
  // 1. Regex validation to ensure safe structure (allows relative paths/subdirectories, strictly ending in .gs or .js, no directory traversal)
  const safePattern = /^(?:\.\/)?(?:[a-zA-Z0-9_\-]+\/)*[a-zA-Z0-9_\-]+\.(gs|js)$/;
  if (!safePattern.test(path)) {
    console.warn(`Warning: Expected file ${path} is not allowed (failed safety pattern check), skipping.`);
    return;
  }

  // 2. Resolve to absolute path and check boundary to guarantee it resides strictly in the project directory
  const safePath = pathModule.resolve(__dirname, path);
  const projectRoot = pathModule.resolve(__dirname);
  if (!safePath.startsWith(projectRoot)) {
    console.warn(`Warning: Expected file ${path} resides outside project directory, skipping.`);
    return;
  }

  if (!fs.existsSync(safePath)) {
    console.warn(`Warning: Expected file ${safePath} does not exist, skipping.`);
    return;
  }

  const code = fs.readFileSync(safePath, 'utf8');
  vm.runInNewContext(code, context, safePath);
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
