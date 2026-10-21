/** Per-user settings (allow/block lists, VIP names, own domain) stored in User Properties. */
const Settings = {
  KEY: 'scanner_settings_v1',

  load: function () {
    let stored = {};
    try { stored = JSON.parse(PropertiesService.getUserProperties().getProperty(Settings.KEY) || '{}'); } catch (e) { stored = {}; }
    return {
      internalDomain: stored.internalDomain || '',
      vipNames: stored.vipNames || [],
      allowDomains: stored.allowDomains || [],
      denyDomains: stored.denyDomains || []
    };
  },

  save: function (s) {
    // User properties are capped at 9 KB per value; the lists stay far below that.
    PropertiesService.getUserProperties().setProperty(Settings.KEY, JSON.stringify(s));
    // Cached verdicts depend on the lists, so drop them by bumping the cache generation.
    PropertiesService.getUserProperties().setProperty('cache_generation', String(Date.now()));
  },

  generation: function () {
    return PropertiesService.getUserProperties().getProperty('cache_generation') || '0';
  },

  parseList: function (text) {
    return String(text || '').split(/[\s,;]+/)
      .map(function (s) { return s.trim().toLowerCase().replace(/^@/, ''); })
      .filter(function (s) { return s.length > 0 && s.length < 254; })
      .slice(0, 100);
  },

  parseNames: function (text) {
    return String(text || '').split(/[\n,;]+/)
      .map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0 && s.length < 80; })
      .slice(0, 50);
  },

  addDomain: function (list, domain) {
    const s = Settings.load();
    const other = list === 'allowDomains' ? 'denyDomains' : 'allowDomains';
    s[other] = s[other].filter(function (d) { return d !== domain; });
    if (s[list].indexOf(domain) < 0) s[list].push(domain);
    Settings.save(s);
  }
};
