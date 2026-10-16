'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { discover } = require('./discover');
const C = require('./checks');
const { finding } = C;
const { loadPolicy, checkServerPolicy, checkSkillPolicy, applyPolicy, DEFAULT_POLICY } = require('./policy');
const { checkPackageLiveness } = require('./online');
const { sevRank } = require('./rules');

const DOC_EXT = new Set(['.md', '.markdown', '.txt', '.mdx', '.rst']);
const SCRIPT_EXT = new Set(['.sh', '.bash', '.zsh', '.ps1', '.psm1', '.bat', '.cmd', '.py', '.js', '.mjs', '.cjs', '.ts', '.rb', '.pl']);
const DATA_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.env', '.ini', '.cfg']);
const MAX_FILE = 1024 * 1024;

function listFiles(dir, max = 500) {
  const out = [];
  const walk = d => {
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (out.length >= max) return;
      const p = path.join(d, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!['node_modules', '.git', '__pycache__'].includes(e.name)) walk(p); }
      else if (e.isFile()) out.push(p);
    }
  };
  walk(dir);
  return out;
}

function scanSkill(skill) {
  const findings = [];
  const files = listFiles(skill.dir);
  for (const file of files) {
    let st; try { st = fs.statSync(file); } catch { continue; }
    if (st.size > MAX_FILE) continue;
    const ext = path.extname(file).toLowerCase();
    const base = path.basename(file).toLowerCase();
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (text.includes('\u0000')) continue; // binary
    const ctx = { file, target: `skill:${skill.name}` };
    const isSkillMd = base === 'skill.md';
    const isScript = SCRIPT_EXT.has(ext) || text.startsWith('#!');
    if (isSkillMd || DOC_EXT.has(ext)) findings.push(...C.checkInstructions(text, ctx));
    if (isSkillMd || isScript || DOC_EXT.has(ext)) findings.push(...C.checkScript(text, ctx));
    if (isSkillMd || isScript || DOC_EXT.has(ext) || DATA_EXT.has(ext) || base.startsWith('.env')) findings.push(...C.findSecretsInText(text, ctx));
    if (isSkillMd) {
      const fm = C.parseFrontmatter(text);
      if (!fm || !fm.name || !fm.description) findings.push(finding('MCP018', { ...ctx, message: 'SKILL.md should start with YAML frontmatter containing name and description' }));
    }
  }
  return { findings, fileCount: files.length };
}

function serverIdentity(name, def) {
  const pkg = C.packageOf(def);
  let host = null;
  try { if (def.url) host = new URL(def.url).hostname; } catch {}
  return { name, package: pkg ? pkg.name : null, host, pkg };
}

/** Load a tools/list dump (from an MCP server) and check its descriptions. */
function scanToolsFile(file) {
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
  const tools = Array.isArray(json) ? json : (json.tools || (json.result && json.result.tools) || []);
  const out = [];
  for (const t of tools) out.push(...C.checkToolDescription(t, { file, target: `tool:${t.name}` }));
  return { findings: out, count: tools.length };
}

/**
 * Main scan. opts: discover opts + { policy, policyFile, online, fetchImpl, toolsFiles }
 */
async function scan(opts = {}) {
  const started = new Date();
  const home = opts.home || os.homedir();
  const policy = opts.policy || (opts.policyFile !== undefined || opts.usePolicy !== false ? loadPolicy(opts.policyFile) : { ...DEFAULT_POLICY });
  const d = discover(opts);
  let findings = [];
  const servers = [];
  const notes = [];

  for (const cfg of d.configs) {
    if (cfg.error) findings.push(finding('MCP017', { file: cfg.file, message: cfg.error }));
    // secrets anywhere in the raw config file text (e.g. top-level tokens) — but only report ones not already tied to a server
    for (const s of cfg.servers) {
      const ctx = { file: cfg.file };
      const ident = serverIdentity(s.name, s.def);
      const pol = checkServerPolicy(policy, ident, ctx);
      const sf = [...C.checkServer(s.name, s.def, ctx, { home }), ...pol.findings];
      if (opts.online && ident.pkg) {
        try { sf.push(...await checkPackageLiveness(ident.pkg, { ...ctx, target: s.name }, { fetchImpl: opts.fetchImpl })); }
        catch (e) { notes.push(`online check failed for ${s.name}: ${e.message}`); }
      }
      servers.push({ client: cfg.client, file: cfg.file, scope: s.scope, name: s.name, transport: s.def.url ? (s.def.type || 'http') : 'stdio', package: ident.pkg ? ident.pkg.spec : null, url: s.def.url ? safeUrl(s.def.url) : null, allowedByPolicy: pol.allowed, findingCount: sf.length });
      findings.push(...sf);
    }
  }

  const skills = [];
  for (const sk of d.skills) {
    const pol = checkSkillPolicy(policy, sk.name, { file: path.join(sk.dir, 'SKILL.md') });
    const r = scanSkill(sk);
    findings.push(...r.findings, ...pol.findings);
    skills.push({ source: sk.source, name: sk.name, dir: sk.dir, files: r.fileCount, allowedByPolicy: pol.allowed, findingCount: r.findings.length + pol.findings.length });
  }

  for (const tf of opts.toolsFiles || []) {
    const r = scanToolsFile(tf);
    findings.push(...r.findings);
    notes.push(`scanned ${r.count} tool descriptions from ${tf}`);
  }

  findings = dedupe(applyPolicy(policy, findings));
  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || String(a.file).localeCompare(String(b.file)));
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return {
    tool: { name: 'mcpscan', version: require('../package.json').version },
    startedAt: started.toISOString(),
    host: { platform: process.platform, online: !!opts.online },
    policy: { source: policy.source || null, failOn: policy.failOn },
    summary: { configsFound: d.configs.length, servers: servers.length, skills: skills.length, findings: findings.length, counts },
    configs: d.configs.map(c => ({ client: c.client, file: c.file, servers: c.servers.length, error: c.error || null })),
    servers, skills, findings, notes,
    checkedConfigPaths: d.checkedConfigPaths,
  };
}

function safeUrl(u) {
  try { const x = new URL(u); x.username = ''; x.password = ''; for (const k of [...x.searchParams.keys()]) x.searchParams.set(k, '***'); return x.toString(); } catch { return '[unparseable url]'; }
}

function dedupe(fs_) {
  const seen = new Set();
  return fs_.filter(f => { const k = [f.ruleId, f.file, f.line, f.target, f.message].join('|'); if (seen.has(k)) return false; seen.add(k); return true; });
}

function exitCodeFor(result, failOn = 'high') {
  if (failOn === 'none') return 0;
  return result.findings.some(f => sevRank(f.severity) >= sevRank(failOn)) ? 1 : 0;
}

module.exports = { scan, scanSkill, scanToolsFile, exitCodeFor, safeUrl };
