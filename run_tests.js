const fs = require('fs');
const vm = require('vm');

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
    return {
      getHeaders: () => ({}),
      getResponseCode: () => 200,
      getContentText: () => '{}'
    };
  }
};

const mockPropertiesService = {
  getScriptProperties: () => ({ getProperty: () => 'MOCK_KEY' })
};

const mockUtilities = {
  unzip: () => { throw new Error('password'); }, // To test encrypted zip detection
  computeDigest: () => [1, 2, 3],
  DigestAlgorithm: { SHA_256: 'SHA_256' },
  base64Encode: () => 'base64'
};

const context = {
  CardService: mockCardService,
  UrlFetchApp: mockUrlFetchApp,
  PropertiesService: mockPropertiesService,
  Utilities: mockUtilities,
  GmailApp: mockGmailApp,
  console: console,
  URL: require('url').URL,
  globalThis: {}
};
context.globalThis = context;

function loadFile(path) {
  const code = fs.readFileSync(path, 'utf8');
  vm.runInNewContext(code, context, path);
}

loadFile('Constants.gs');
loadFile('SecurityUtils.gs');
loadFile('UI.gs');
loadFile('Code.gs');
loadFile('tests.js');

context.runTests();
