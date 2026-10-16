'use strict';
const path = require('path');
const { RULES, sevRank } = require('./rules');

const COLORS = { critical: '\x1b[1;31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[90m' };

function text(result, { color = false, minSeverity = 'info' } = {}) {
  const c = (s, t) => color ? `${COLORS[s] || ''}${t}\x1b[0m` : t;
  const L = [];
  const s = result.summary;
  L.push(`mcpscan ${result.tool.version} — ${s.configsFound} config file(s), ${s.servers} MCP server(s), ${s.skills} skill(s)`);
  for (const cfg of result.configs) L.push(`  config  ${cfg.client.padEnd(22)} ${cfg.file} (${cfg.servers} servers)${cfg.error ? ' [PARSE ERROR]' : ''}`);
  for (const sk of result.skills) L.push(`  skill   ${sk.source.padEnd(22)} ${sk.dir}`);
  L.push('');
  const shown = result.findings.filter(f => sevRank(f.severity) >= sevRank(minSeverity));
  if (!shown.length) L.push('No findings.');
  for (const f of shown) {
    L.push(`${c(f.severity, `[${f.severity.toUpperCase()}]`.padEnd(11))}${f.ruleId} ${f.rule}  ${f.target ? `(${f.target})` : ''}`);
    L.push(`           ${f.message}`);
    if (f.file) L.push(`           at ${f.file}${f.line ? `:${f.line}` : ''}`);
    if (f.evidence) L.push(`           evidence: ${f.evidence}`);
  }
  L.push('');
  const k = s.counts;
  L.push(`Summary: ${s.findings} finding(s) — critical ${k.critical}, high ${k.high}, medium ${k.medium}, low ${k.low}, info ${k.info}`);
  for (const n of result.notes) L.push(`note: ${n}`);
  return L.join('\n');
}

function json(result) { return JSON.stringify(result, null, 2); }

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SEC_SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

function toUri(file) {
  if (!file) return undefined;
  const abs = path.resolve(file).replace(/\\/g, '/');
  return 'file://' + (abs.startsWith('/') ? '' : '/') + encodeURI(abs);
}

function sarif(result) {
  const used = [...new Set(result.findings.map(f => f.ruleId))];
  const rules = Object.entries(RULES).map(([id, r]) => ({
    id, name: r.name, shortDescription: { text: r.title },
    defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
    properties: { 'security-severity': SEC_SCORE[r.severity], tags: ['security', 'mcp', 'supply-chain'] },
  }));
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'mcpscan', version: result.tool.version, informationUri: 'https://modelcontextprotocol.io', rules } },
      results: result.findings.map(f => ({
        ruleId: f.ruleId,
        ruleIndex: Object.keys(RULES).indexOf(f.ruleId),
        level: SARIF_LEVEL[f.severity],
        message: { text: `${f.message}${f.target ? ` [${f.target}]` : ''}` },
        locations: f.file ? [{ physicalLocation: { artifactLocation: { uri: toUri(f.file) }, ...(f.line ? { region: { startLine: f.line } } : {}) } }] : [],
        properties: { severity: f.severity, target: f.target },
      })),
      properties: { usedRules: used },
    }],
  }, null, 2);
}

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function html(result) {
  const s = result.summary;
  const rows = result.findings.map(f => `<tr class="${f.severity}"><td><span class="sev ${f.severity}">${f.severity}</span></td><td>${esc(f.ruleId)}<br><small>${esc(f.rule)}</small></td><td>${esc(f.target)}</td><td>${esc(f.message)}${f.evidence ? `<br><code>${esc(f.evidence)}</code>` : ''}</td><td><small>${esc(f.file)}${f.line ? ':' + f.line : ''}</small></td></tr>`).join('\n');
  const srv = result.servers.map(x => `<tr><td>${esc(x.client)}</td><td>${esc(x.name)}</td><td>${esc(x.transport)}</td><td>${esc(x.package || x.url || '')}</td><td>${x.findingCount}</td></tr>`).join('\n');
  const sk = result.skills.map(x => `<tr><td>${esc(x.source)}</td><td>${esc(x.name)}</td><td><small>${esc(x.dir)}</small></td><td>${x.findingCount}</td></tr>`).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>mcpscan report</title>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#222}table{border-collapse:collapse;width:100%;margin-bottom:2rem}td,th{border:1px solid #ddd;padding:.4rem;vertical-align:top;text-align:left}th{background:#f4f4f4}.sev{padding:2px 6px;border-radius:4px;color:#fff;font-weight:600;text-transform:uppercase;font-size:.75rem}.critical{background:#7f1d1d}.high{background:#dc2626}.medium{background:#d97706}.low{background:#0891b2}.info{background:#6b7280}tr.critical,tr.high,tr.medium,tr.low,tr.info{background:none}code{background:#f4f4f4;padding:1px 4px;word-break:break-all}.cards span{display:inline-block;margin-right:1rem;padding:.5rem 1rem;border-radius:6px;color:#fff}</style></head><body>
<h1>mcpscan report</h1><p>Generated ${esc(result.startedAt)} on ${esc(result.host.platform)} · mcpscan ${esc(result.tool.version)} · ${s.configsFound} configs · ${s.servers} servers · ${s.skills} skills</p>
<p class="cards"><span class="critical">Critical ${s.counts.critical}</span><span class="high">High ${s.counts.high}</span><span class="medium">Medium ${s.counts.medium}</span><span class="low">Low ${s.counts.low}</span><span class="info">Info ${s.counts.info}</span></p>
<h2>Findings</h2><table><tr><th>Severity</th><th>Rule</th><th>Target</th><th>Detail</th><th>Location</th></tr>${rows || '<tr><td colspan="5">No findings</td></tr>'}</table>
<h2>MCP servers</h2><table><tr><th>Client</th><th>Name</th><th>Transport</th><th>Package / URL</th><th>Findings</th></tr>${srv}</table>
<h2>Skills</h2><table><tr><th>Source</th><th>Name</th><th>Folder</th><th>Findings</th></tr>${sk}</table>
<p><small>Secret values are masked. Generated by mcpscan (MIT).</small></p></body></html>`;
}

function render(result, format, opts) {
  switch (format) {
    case 'json': return json(result);
    case 'sarif': return sarif(result);
    case 'html': return html(result);
    default: return text(result, opts);
  }
}

module.exports = { render, text, json, sarif, html, esc };
