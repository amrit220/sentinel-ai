/* API client + tiny helpers */
const API = {
  async req(method, url, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON */ }
    if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
    return data;
  },
  get: (u) => API.req('GET', u),
  post: (u, b) => API.req('POST', u, b || {}),
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&' + 'amp;', '<': '&' + 'lt;', '>': '&' + 'gt;', '"': '&' + 'quot;', "'": '&' + '#39;' }[c]));

const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '—';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLOR = { critical: '#ff3b5c', high: '#ff8b3d', medium: '#ffd23d', low: '#4dd8ff', info: '#8b95a5' };
