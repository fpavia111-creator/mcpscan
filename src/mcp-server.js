'use strict';
/**
 * Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0), zero dependencies.
 * All tools are read-only: they discover and scan, never modify files or configs.
 */
const readline = require('readline');
const fs = require('fs');
const { scan, scanSkill } = require('./scan');
const { discover } = require('./discover');
const C = require('./checks');
const { text } = require('./report');

const PROTOCOL_VERSION = '2025-06-18';
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

const TOOLS = [
  { name: 'scan_all', description: 'Discover MCP configs and skills on this machine (plus optional project dirs) and return security findings. Read-only; offline.',
    inputSchema: { type: 'object', properties: { projects: { type: 'array', items: { type: 'string' }, description: 'Project directories to include' }, minSeverity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] } } }, annotations: RO },
  { name: 'list_discovered', description: 'List discovered MCP config files, servers and skill folders without running checks. Read-only.',
    inputSchema: { type: 'object', properties: { projects: { type: 'array', items: { type: 'string' } } } }, annotations: RO },
  { name: 'scan_skill', description: 'Scan one skill folder (a directory containing SKILL.md). Read-only.',
    inputSchema: { type: 'object', properties: { dir: { type: 'string' } }, required: ['dir'] }, annotations: RO },
  { name: 'scan_text', description: 'Scan arbitrary text (e.g. a tool description or SKILL.md draft) for prompt injection, hidden unicode, dangerous commands and secrets. Read-only.',
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] }, annotations: RO },
];

async function callTool(name, args = {}) {
  const sevOrder = ['info', 'low', 'medium', 'high', 'critical'];
  if (name === 'scan_all') {
    const r = await scan({ projects: args.projects || [] });
    const min = sevOrder.indexOf(args.minSeverity || 'info');
    r.findings = r.findings.filter(f => sevOrder.indexOf(f.severity) >= min);
    return { content: [{ type: 'text', text: text(r) }], structuredContent: { summary: r.summary, findings: r.findings } };
  }
  if (name === 'list_discovered') {
    const d = discover({ projects: args.projects || [] });
    const out = { configs: d.configs.map(c => ({ client: c.client, file: c.file, servers: c.servers.map(s => s.name), error: c.error || null })), skills: d.skills };
    return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], structuredContent: out };
  }
  if (name === 'scan_skill') {
    if (!args.dir || !fs.existsSync(args.dir)) throw new Error('dir not found');
    const r = scanSkill({ dir: args.dir, name: require('path').basename(args.dir) });
    return { content: [{ type: 'text', text: JSON.stringify(r.findings, null, 2) }], structuredContent: { findings: r.findings } };
  }
  if (name === 'scan_text') {
    const t = String(args.text || '');
    const f = [...C.checkInstructions(t, { target: 'text' }), ...C.checkScript(t, { target: 'text' }), ...C.findSecretsInText(t, { target: 'text' })];
    return { content: [{ type: 'text', text: f.length ? JSON.stringify(f, null, 2) : 'No findings.' }], structuredContent: { findings: f } };
  }
  throw Object.assign(new Error(`Unknown tool: ${name}`), { code: -32602 });
}

async function handle(msg) {
  const { id, method, params } = msg;
  const ok = result => ({ jsonrpc: '2.0', id, result });
  const err = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  if (id === undefined) return null; // notification
  switch (method) {
    case 'initialize':
      return ok({ protocolVersion: (params && params.protocolVersion) || PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'mcpscan', version: require('../package.json').version }, instructions: 'Read-only security scanner for MCP configs and agent skills. Secret values are always masked.' });
    case 'ping': return ok({});
    case 'tools/list': return ok({ tools: TOOLS });
    case 'tools/call':
      try { return ok(await callTool(params && params.name, params && params.arguments)); }
      catch (e) { return e.code ? err(e.code, e.message) : ok({ content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }); }
    default: return err(-32601, `Method not found: ${method}`);
  }
}

function start(input = process.stdin, output = process.stdout) {
  const rl = readline.createInterface({ input });
  rl.on('line', async line => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'); return; }
    const res = await handle(msg);
    if (res) output.write(JSON.stringify(res) + '\n');
  });
  return rl;
}

module.exports = { start, handle, TOOLS };
