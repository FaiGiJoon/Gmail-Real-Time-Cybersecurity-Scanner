const ids = ['sb', 'internal', 'vip', 'allow', 'deny'];
const el = (id) => document.getElementById(id);
const list = (v) => String(v || '').split(/[\s,;]+/).map((s) => s.trim().toLowerCase().replace(/^@/, '')).filter(Boolean).slice(0, 100);
const names = (v) => String(v || '').split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean).slice(0, 50);

document.addEventListener('DOMContentLoaded', async () => {
  const s = await chrome.storage.local.get(['SAFE_BROWSING_API_KEY', 'config']);
  const c = s.config || {};
  el('sb').value = s.SAFE_BROWSING_API_KEY || '';
  el('internal').value = c.internalDomain || '';
  el('vip').value = (c.vipNames || []).join(', ');
  el('allow').value = (c.allowDomains || []).join(', ');
  el('deny').value = (c.denyDomains || []).join(', ');
  el('save').addEventListener('click', async () => {
    await chrome.storage.local.set({
      SAFE_BROWSING_API_KEY: el('sb').value.trim(),
      config: { internalDomain: list(el('internal').value)[0] || '', vipNames: names(el('vip').value), allowDomains: list(el('allow').value), denyDomains: list(el('deny').value) }
    });
    el('status').textContent = 'Saved.';
    setTimeout(() => { el('status').textContent = ''; }, 2500);
  });
});
