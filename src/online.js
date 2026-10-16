'use strict';
const { finding } = require('./checks');

/** Optional liveness checks. `fetchImpl` is injectable so tests never touch the network. */
async function getJson(fetchImpl, url, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { signal: ctrl.signal, headers: { accept: 'application/json', 'user-agent': 'mcpscan' } });
    if (res.status === 404) return { status: 404 };
    if (!res.ok) return { status: res.status, error: `HTTP ${res.status}` };
    return { status: res.status, json: await res.json() };
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'timeout' : e.message };
  } finally { clearTimeout(t); }
}

function githubRepo(repo) {
  const url = typeof repo === 'string' ? repo : repo && repo.url;
  const m = url && url.match(/github\.com[/:]([^/]+)\/([^/#.]+)/i);
  return m ? `${m[1]}/${m[2]}` : null;
}

async function checkPackageLiveness(pkg, ctx, { fetchImpl = globalThis.fetch, staleDays = 365, timeoutMs = 8000, now = Date.now() } = {}) {
  const out = [];
  if (!pkg || pkg.ecosystem !== 'npm' || pkg.version === 'url') return out;
  const r = await getJson(fetchImpl, `https://registry.npmjs.org/${pkg.name.replace('/', '%2F')}`, timeoutMs);
  if (r.status === 404) { out.push(finding('MCP016', { ...ctx, message: `npm package "${pkg.name}" does not exist in the registry`, evidence: pkg.name })); return out; }
  if (!r.json) return out; // network failure: stay silent, reported as note by caller
  const doc = r.json;
  const latest = doc['dist-tags'] && doc['dist-tags'].latest;
  const v = (pkg.version && doc.versions && doc.versions[pkg.version]) || (latest && doc.versions && doc.versions[latest]) || {};
  if (v.deprecated) out.push(finding('MCP013', { ...ctx, message: `npm package "${pkg.name}@${v.version || latest}" is deprecated: ${String(v.deprecated).slice(0, 160)}` }));
  const lastPub = doc.time && (doc.time[latest] || doc.time.modified);
  if (lastPub) {
    const days = Math.floor((now - Date.parse(lastPub)) / 86400000);
    if (days > staleDays) out.push(finding('MCP014', { ...ctx, message: `npm package "${pkg.name}" last published ${days} days ago (${lastPub.slice(0, 10)})` }));
  }
  const gh = githubRepo(doc.repository || v.repository);
  if (gh) {
    const g = await getJson(fetchImpl, `https://api.github.com/repos/${gh}`, timeoutMs);
    if (g.json && g.json.archived) out.push(finding('MCP015', { ...ctx, message: `GitHub repo ${gh} is archived (read-only, no fixes)` }));
    if (g.status === 404) out.push(finding('MCP015', { ...ctx, severity: 'medium', message: `GitHub repo ${gh} referenced by package no longer exists` }));
  }
  return out;
}

module.exports = { checkPackageLiveness, githubRepo };
