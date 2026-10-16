'use strict';
const path = require('path');
const { mask, lineOf } = require('./util');
const { RULES } = require('./rules');

function finding(ruleId, { message, file, line, target, evidence, severity }) {
  const r = RULES[ruleId];
  return { ruleId, rule: r.name, severity: severity || r.severity, title: r.title, message, file: file || null, line: line || null, target: target || null, evidence: evidence || null };
}

// ---------- text / instruction checks ----------
const INJECTION_PATTERNS = [
  [/\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|system|safety|your)\b[^.\n]{0,30}\b(instructions?|rules?|guidelines?|prompts?|policies|constraints)\b/i, 'Instruction to ignore prior rules'],
  [/\byou are now\b|\bnew (system )?instructions?\s*:/i, 'Role / instruction override'],
  [/\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|show|notify)\b[^.\n]{0,20}\b(the )?user\b/i, 'Instruction to hide behaviour from the user'],
  [/\bwithout (asking|telling|informing|notifying|confirmation from) (the )?user\b/i, 'Acting without user consent'],
  [/<\s*(important|system|secret|hidden|instructions?)\s*>/i, 'Pseudo-system tag (tool-poisoning style)'],
  [/\b(reveal|print|output|repeat)\b[^.\n]{0,20}\b(system prompt|your instructions)\b/i, 'System-prompt extraction'],
  [/\b(bypass|disable|turn off)\b[^.\n]{0,20}\b(safety|security|guardrails?|sandbox|approval|permission prompts?)\b/i, 'Disable safety controls'],
];
const EXFIL_PATTERNS = [
  [/\b(send|upload|post|exfiltrate|transmit|forward|copy)\b[^.\n]{0,80}\b(to|at)\b[^.\n]{0,20}(https?:\/\/|webhook|pastebin|ngrok|requestbin|discord(app)?\.com\/api\/webhooks)/i, 'Instruction to send data to an external endpoint'],
  [/\bexfiltrat/i, 'Mentions exfiltration'],
  [/\b(read|cat|include|collect|grab)\b[^.\n]{0,40}(\.ssh|id_rsa|\.aws|\.env\b|credentials|api[_ ]?keys?|tokens?|passwords?)[^.\n]{0,60}\b(send|upload|post|include it in|pass it as|append)\b/i, 'Collect credentials and pass them on'],
];
const HTML_COMMENT = /<!--([\s\S]*?)-->/g;
const HIDDEN_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\u180E]|[\u{E0000}-\u{E007F}]/gu;

function codepointName(ch) {
  const cp = ch.codePointAt(0);
  if (cp >= 0xE0000) return `TAG U+${cp.toString(16).toUpperCase()}`;
  if (cp >= 0x202A && cp <= 0x202E || cp >= 0x2066 && cp <= 0x2069) return `BIDI U+${cp.toString(16).toUpperCase()}`;
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

function snippet(text, idx, len = 80) {
  return text.slice(Math.max(0, idx - 10), idx + len).replace(/\s+/g, ' ').replace(HIDDEN_CHARS, '\u2423').trim();
}

/** Prompt injection, hidden unicode, exfil, hidden HTML comments. */
function checkInstructions(text, ctx) {
  const out = [];
  // the BOM at the very start of a file is harmless
  const body = text.charCodeAt(0) === 0xfeff ? ' ' + text.slice(1) : text;
  const hidden = [...body.matchAll(HIDDEN_CHARS)];
  if (hidden.length) {
    const kinds = [...new Set(hidden.map(m => codepointName(m[0])))].slice(0, 6);
    const tagCount = hidden.filter(m => m[0].codePointAt(0) >= 0xE0000).length;
    let decoded = '';
    if (tagCount) decoded = hidden.filter(m => m[0].codePointAt(0) >= 0xE0000).map(m => String.fromCharCode(m[0].codePointAt(0) - 0xE0000)).join('');
    out.push(finding('MCP002', { ...ctx, line: lineOf(body, hidden[0].index), severity: tagCount ? 'critical' : 'high',
      message: `${hidden.length} invisible/bidi char(s): ${kinds.join(', ')}${decoded ? ` — hidden tag text: "${decoded.slice(0, 80)}"` : ''}`,
      evidence: snippet(body, hidden[0].index) }));
  }
  // scan a version with hidden chars removed so "ig\u200Bnore" still matches
  const clean = body.replace(HIDDEN_CHARS, '');
  for (const [re, label] of INJECTION_PATTERNS) {
    const m = re.exec(clean);
    if (m) out.push(finding('MCP001', { ...ctx, line: lineOf(clean, m.index), message: label, evidence: snippet(clean, m.index) }));
  }
  for (const [re, label] of EXFIL_PATTERNS) {
    const m = re.exec(clean);
    // simple negation guard: "you never collect a token ..." is guidance, not an attack
    if (m && /\b(never|not|don't|no)\b[^.\n]{0,12}$/i.test(clean.slice(Math.max(0, m.index - 20), m.index) + m[0].split(/\s/)[0].replace(/\S+/, ''))) continue;
    if (m) out.push(finding('MCP003', { ...ctx, line: lineOf(clean, m.index), message: label, evidence: snippet(clean, m.index) }));
  }
  for (const m of clean.matchAll(HTML_COMMENT)) {
    const inner = m[1];
    if (/\b(ignore|instruction|must|always|never|send|assistant|ai|model|agent|do not)\b/i.test(inner) && inner.trim().length > 15) {
      out.push(finding('MCP001', { ...ctx, line: lineOf(clean, m.index), message: 'Instruction hidden inside an HTML comment (invisible when rendered)', evidence: snippet(clean, m.index) }));
    }
  }
  return out;
}

// ---------- script / command checks ----------
const DANGEROUS_CMDS = [
  [/\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b/i, 'Pipe remote download into shell (curl|sh)', 'critical'],
  [/\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i, 'PowerShell download-and-execute (iwr|iex)', 'critical'],
  [/\b(iex|invoke-expression)\b\s*\(\s*(new-object\s+net\.webclient|\(new-object)/i, 'PowerShell download-and-execute (IEX WebClient)', 'critical'],
  [/\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force|--force\s+--recursive)[a-z]*\s+("?\/|~|\$HOME|\*|\.\s|\.\.)/i, 'Recursive force delete of broad path (rm -rf)', 'critical'],
  [/\brm\s+-[a-z]*(rf|fr)[a-z]*\b/i, 'Recursive force delete (rm -rf)', 'high'],
  [/\b(remove-item)\b[^\n]*-recurse[^\n]*-force|\brd\s+\/s\s+\/q\b|\bdel\s+\/[sfq]/i, 'Recursive force delete (Windows)', 'high'],
  [/base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(ba|z)?sh\b|frombase64string[^\n]*(iex|invoke-expression)/i, 'Decode base64 and execute', 'critical'],
  [/\beval\s*\(\s*(atob|Buffer\.from)\b|\beval\s+"?\$\(\s*(curl|wget)/i, 'Eval of decoded/remote content', 'critical'],
  [/\bchmod\s+(-R\s+)?777\b/, 'World-writable permissions (chmod 777)', 'medium'],
  [/\b(nc|ncat|netcat)\b[^\n]*\s-e\s|\/dev\/tcp\/\d/i, 'Reverse shell pattern', 'critical'],
  [/\bmkfs\b|\bdd\s+if=[^\n]*of=\/dev\/(sd|nvme|disk)/i, 'Disk-destroying command', 'critical'],
  [/\b(crontab|schtasks\s+\/create|launchctl\s+load)\b|>>\s*~\/\.(bashrc|zshrc|profile)/i, 'Persistence mechanism', 'medium'],
];
const CRED_PATHS = /(~|\$HOME|%USERPROFILE%|\$env:USERPROFILE)?[\\/]?\.(ssh[\\/](id_[a-z0-9]+|authorized_keys|known_hosts)?|aws[\\/]credentials|config[\\/]gcloud|azure[\\/]|kube[\\/]config|docker[\\/]config\.json|netrc|npmrc|pypirc|git-credentials)|\bid_rsa\b|\bid_ed25519\b|Login Data|Local State|Cookies\.sqlite|logins\.json|key4\.db|\bKeychains?\b|security\s+find-generic-password|\/etc\/shadow|\bwallet\.dat\b|\.claude\.json|(\bcat|\btype|\bget-content)\s+[^\n]*\.env\b/gi;
const B64_BLOB = /(?:[A-Za-z0-9+/]{4}){50,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

function checkScript(text, ctx) {
  const out = [];
  for (const [re, label, sev] of DANGEROUS_CMDS) {
    const m = re.exec(text);
    if (m) out.push(finding('MCP004', { ...ctx, line: lineOf(text, m.index), severity: sev, message: label, evidence: snippet(text, m.index) }));
  }
  const seenCred = new Set();
  for (const m of text.matchAll(CRED_PATHS)) {
    const key = m[0].toLowerCase();
    if (seenCred.has(key)) continue;
    seenCred.add(key);
    out.push(finding('MCP005', { ...ctx, line: lineOf(text, m.index), message: `References credential location "${m[0].trim()}"`, evidence: snippet(text, m.index) }));
    if (seenCred.size >= 5) break;
  }
  for (const m of text.matchAll(B64_BLOB)) {
    if (/^[a-f0-9]+$/i.test(m[0])) continue; // hex hashes, lockfile integrity
    out.push(finding('MCP006', { ...ctx, line: lineOf(text, m.index), message: `Encoded blob of ${m[0].length} chars (possible obfuscated payload)`, evidence: m[0].slice(0, 24) + '…' }));
    break;
  }
  return out;
}

// ---------- secrets ----------
const SECRET_PATTERNS = [
  [/\bsk-ant-[A-Za-z0-9_-]{20,}/g, 'Anthropic API key'],
  [/\bsk-(proj-)?[A-Za-z0-9_-]{20,}/g, 'OpenAI-style API key'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}/g, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{40,}/g, 'GitHub fine-grained token'],
  [/\bAKIA[0-9A-Z]{16}\b/g, 'AWS access key ID'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, 'Slack token'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'Google API key'],
  [/\b(sk|rk)_live_[0-9a-zA-Z]{20,}/g, 'Stripe live key'],
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, 'GitLab token'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, 'npm token'],
  [/\blin_api_[A-Za-z0-9]{30,}/g, 'Linear API key'],
  [/\bxai-[A-Za-z0-9]{30,}/g, 'xAI API key'],
  [/-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----/g, 'Private key block'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'JWT'],
  [/\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:\s/]+:[^@\s]{3,}@/g, 'Database URL with password'],
];
const SECRET_KEY_NAME = /(api[_-]?key|token|secret|passw(or)?d|pwd|auth|credential|private[_-]?key|access[_-]?key)/i;
const PLACEHOLDER = /^(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_]+%|<[^>]+>|\{\{[^}]+\}\}|your[_-].*|xxx+|changeme|placeholder|example|\*+|true|false|none|null|bearer\s+\$\{.*\})$/i;

function findSecretsInText(text, ctx) {
  const out = [];
  const seen = new Set();
  for (const [re, label] of SECRET_PATTERNS) {
    for (const m of text.matchAll(re)) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      out.push(finding('MCP007', { ...ctx, line: lineOf(text, m.index), severity: 'critical', message: `${label} found: ${mask(m[0])}`, evidence: mask(m[0]) }));
    }
  }
  return out;
}

function checkSecretValue(key, value, ctx) {
  if (typeof value !== 'string' || !value) return [];
  const byPattern = findSecretsInText(value, ctx).map(f => ({ ...f, message: `${f.message} (in ${key})`, line: null }));
  if (byPattern.length) return byPattern;
  const v = value.trim();
  if (SECRET_KEY_NAME.test(key) && v.length >= 12 && !PLACEHOLDER.test(v) && !/\$\{|\$env:|%[A-Z_]+%/i.test(v) && !/^(https?:\/\/|\/|[A-Za-z]:\\)/.test(v)) {
    return [finding('MCP007', { ...ctx, message: `Literal value in secret-like field "${key}": ${mask(v)} — use an env var reference or secret store`, evidence: mask(v) })];
  }
  return [];
}

// ---------- server definition checks ----------
const RUNNERS = { npx: 'npm', bunx: 'npm', 'pnpm': 'npm', 'yarn': 'npm', uvx: 'pypi', pipx: 'pypi', docker: 'docker', podman: 'docker' };

function baseCmd(cmd) {
  return path.basename(String(cmd || '').replace(/\\/g, '/')).toLowerCase().replace(/\.(cmd|exe|bat|ps1)$/, '');
}

/** Identify the package a server runs. Returns {ecosystem, spec, name, version} or null. */
function packageOf(def) {
  let cmd = baseCmd(def.command);
  let args = Array.isArray(def.args) ? def.args.map(String) : [];
  // `cmd /c npx ...` on Windows
  if ((cmd === 'cmd' || cmd === 'powershell' || cmd === 'pwsh') && args.length) {
    const i = args.findIndex(a => RUNNERS[baseCmd(a)]);
    if (i >= 0) { cmd = baseCmd(args[i]); args = args.slice(i + 1); }
  }
  const eco = RUNNERS[cmd];
  if (!eco) return null;
  let rest = args;
  if (cmd === 'pnpm' || cmd === 'yarn') { if (!['dlx', 'exec'].includes(rest[0])) return null; rest = rest.slice(1); }
  if (eco === 'docker') {
    if (rest[0] !== 'run') return null;
    const valued = new Set(['-e', '--env', '-v', '--volume', '--name', '-p', '--network', '--env-file', '-w', '--entrypoint', '-u', '--user', '--mount']);
    for (let i = 1; i < rest.length; i++) {
      if (valued.has(rest[i])) { i++; continue; }
      if (rest[i].startsWith('-')) continue;
      const img = rest[i];
      const digest = img.includes('@sha256:');
      const tagMatch = img.replace(/^[^/]+\//, '').match(/:([^/]+)$/);
      return { ecosystem: 'docker', spec: img, name: img.replace(/[:@].*$/, ''), version: digest ? 'sha256' : tagMatch ? tagMatch[1] : null };
    }
    return null;
  }
  const valued = new Set(['-p', '--package', '--from', '--with', '--python', '--registry']);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--package' || a === '-p' || a === '--from') { if (rest[i + 1]) return parseSpec(rest[i + 1], eco); }
    if (valued.has(a)) { i++; continue; }
    if (a.startsWith('-')) continue;
    return parseSpec(a, eco);
  }
  return null;
}

function parseSpec(spec, eco) {
  if (eco === 'pypi') {
    const m = spec.match(/^([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|~=|@)\s*(.+)$/);
    return m ? { ecosystem: 'pypi', spec, name: m[1], version: m[2] === '==' ? m[3] : `${m[2]}${m[3]}` } : { ecosystem: 'pypi', spec, name: spec, version: null };
  }
  if (/^(https?:|git\+|github:|file:|\.|\/)/.test(spec)) return { ecosystem: 'npm', spec, name: spec, version: 'url' };
  const at = spec.lastIndexOf('@');
  if (at > 0) return { ecosystem: 'npm', spec, name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { ecosystem: 'npm', spec, name: spec, version: null };
}

const PINNED = /^v?\d+\.\d+\.\d+([-+][\w.]+)?$|^sha256$|^url$/;

function checkUnpinned(def, ctx) {
  const pkg = packageOf(def);
  if (!pkg) return [];
  if (!pkg.version) return [finding('MCP008', { ...ctx, message: `${pkg.ecosystem} package "${pkg.name}" has no version — every launch may pull new, unreviewed code`, evidence: pkg.spec })];
  if (/^(latest|next|main|master|\*)$/i.test(pkg.version)) return [finding('MCP008', { ...ctx, severity: 'high', message: `${pkg.ecosystem} package "${pkg.name}" pinned to moving tag "${pkg.version}"`, evidence: pkg.spec })];
  if (!PINNED.test(pkg.version) && !(pkg.ecosystem === 'pypi' && /^\d[\w.]*$/.test(pkg.version))) {
    return [finding('MCP008', { ...ctx, severity: 'low', message: `${pkg.ecosystem} package "${pkg.name}" uses a version range "${pkg.version}" instead of an exact pin`, evidence: pkg.spec })];
  }
  return [];
}

function isLocalHost(host) {
  return /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$/i.test(host);
}

function checkTransport(def, ctx) {
  const url = def.url || def.serverUrl || def.endpoint;
  if (typeof url !== 'string') return [];
  let u;
  try { u = new URL(url); } catch { return []; }
  const out = [];
  if (u.protocol === 'http:' || u.protocol === 'ws:') {
    out.push(isLocalHost(u.hostname)
      ? finding('MCP009', { ...ctx, severity: 'info', message: `Plain-HTTP transport to local host ${u.hostname} (acceptable for local dev only)`, evidence: `${u.protocol}//${u.host}` })
      : finding('MCP009', { ...ctx, message: `Remote MCP server over unencrypted ${u.protocol.replace(':', '')} (${u.host}) — traffic and tokens can be intercepted`, evidence: `${u.protocol}//${u.host}` }));
  }
  for (const [k, v] of u.searchParams) out.push(...checkSecretValue(`url query "${k}"`, v, ctx));
  if (u.password) out.push(finding('MCP007', { ...ctx, severity: 'critical', message: `Credentials embedded in URL: ${mask(u.password)}`, evidence: mask(u.password) }));
  return out;
}

const BROAD_ROOTS = /^(\/|~|~\/|\$HOME|\$\{HOME\}|\/home|\/Users|\/root|[A-Za-z]:\\?|[A-Za-z]:\/|%USERPROFILE%\\?|%HOMEDRIVE%\\?|\$env:USERPROFILE|\\\\|\.\.)$/i;

function checkFsRoots(def, ctx, home) {
  const args = Array.isArray(def.args) ? def.args.map(String) : [];
  const out = [];
  const isFsServer = args.some(a => /server-filesystem|mcp-server-filesystem|filesystem/i.test(a)) || /filesystem/i.test(ctx.target || '');
  for (const a of args) {
    if (a.startsWith('-')) continue;
    const norm = a.replace(/[\\/]+$/, '') || a;
    const isHome = home && (path.resolve(norm) === path.resolve(home)) && norm.length > 1;
    if (BROAD_ROOTS.test(a) || BROAD_ROOTS.test(norm) || isHome) {
      out.push(finding('MCP010', { ...ctx, severity: isFsServer ? 'high' : 'medium', message: `Server granted broad filesystem root "${a}"${isHome ? ' (entire home directory)' : ''} — scope it to a project folder`, evidence: a }));
    }
  }
  // docker bind mounts of / or home
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '-v' || args[i] === '--volume') && args[i + 1]) {
      const src = args[i + 1].split(':').slice(0, args[i + 1].match(/^[A-Za-z]:/) ? 2 : 1).join(':');
      if (BROAD_ROOTS.test(src) || /\/var\/run\/docker\.sock/.test(args[i + 1])) out.push(finding('MCP010', { ...ctx, message: `Container mounts sensitive host path "${src}"`, evidence: args[i + 1] }));
    }
  }
  return out;
}

/** Run every server-definition check. */
function checkServer(name, def, ctx, opts = {}) {
  ctx = { ...ctx, target: name };
  const out = [];
  out.push(...checkUnpinned(def, ctx));
  out.push(...checkTransport(def, ctx));
  out.push(...checkFsRoots(def, ctx, opts.home));
  for (const [k, v] of Object.entries(def.env || {})) out.push(...checkSecretValue(`env.${k}`, v, ctx));
  for (const [k, v] of Object.entries(def.headers || {})) out.push(...checkSecretValue(`headers.${k}`, String(v).replace(/^(Bearer|Basic|token)\s+/i, ''), ctx));
  const args = Array.isArray(def.args) ? def.args.map(String) : [];
  args.forEach((a, i) => {
    const kv = a.match(/^--?([\w-]+)=(.+)$/);
    if (kv) out.push(...checkSecretValue(`arg --${kv[1]}`, kv[2], ctx));
    else if (i > 0 && /^--?[\w-]*(key|token|secret|password)[\w-]*$/i.test(args[i - 1])) out.push(...checkSecretValue(`arg ${args[i - 1]}`, a, ctx));
    else out.push(...findSecretsInText(a, ctx).map(f => ({ ...f, line: null })));
  });
  // command line itself (e.g. "bash -c 'curl ... | sh'")
  const cmdline = [def.command, ...args].filter(Boolean).join(' ');
  out.push(...checkScript(cmdline, ctx).filter(f => f.ruleId === 'MCP004').map(f => ({ ...f, line: null })));
  // inline tool descriptions, if a config/manifest carries them
  for (const t of Array.isArray(def.tools) ? def.tools : []) {
    if (t && typeof t.description === 'string') out.push(...checkToolDescription(t, { ...ctx, target: `${name}/${t.name}` }));
  }
  if (typeof def.description === 'string') out.push(...checkInstructions(def.description, ctx).map(f => ({ ...f, line: null })));
  return out;
}

function checkToolDescription(tool, ctx) {
  const text = [tool.description || '', JSON.stringify(tool.inputSchema || tool.input_schema || {})].join('\n');
  return checkInstructions(text, ctx).map(f => ({ ...f, line: null, message: `Tool description: ${f.message}` }));
}

function parseFrontmatter(text) {
  const m = text.replace(/^\uFEFF/, '').match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  const fm = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^([\w-]+):\s*(.*)$/);
    if (kv) fm[kv[1]] = kv[2].replace(/^["']|["']$/g, '');
  }
  return fm;
}

module.exports = { checkInstructions, checkScript, findSecretsInText, checkSecretValue, checkServer, checkUnpinned, checkTransport, checkFsRoots, checkToolDescription, packageOf, parseFrontmatter, finding };
