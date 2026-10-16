#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { scan, exitCodeFor } = require('../src/scan');
const { discover, configCandidates } = require('../src/discover');
const { render } = require('../src/report');
const { loadPolicy } = require('../src/policy');
const { RULES } = require('../src/rules');

const HELP = `mcpscan — MCP server & agent-skill supply-chain scanner

Usage:
  mcpscan [scan] [options]      Discover and scan (default command)
  mcpscan list [options]        Show discovered configs/skills only
  mcpscan paths                 Show every config path checked on this OS
  mcpscan rules                 List rule IDs
  mcpscan init-policy           Write a starter mcpscan.policy.json
  mcpscan mcp                   Run as a read-only MCP server over stdio

Options:
  -p, --project <dir>     Include project-level configs/skills (repeatable; default: cwd)
  -c, --config <file>     Scan an extra MCP config JSON (repeatable)
  -s, --skills <dir>      Scan an extra skills directory (repeatable)
  -t, --tools <file>      Scan a tools/list JSON dump for poisoned descriptions (repeatable)
      --root <home>       Treat <home> as the user home dir (for fixtures / other users)
      --platform <p>      Use win32|darwin|linux path layout (with --root, for fixtures)
      --no-default-roots  Skip user-level locations (only --project/--config/--skills)
  -f, --format <fmt>      text | json | sarif | html   (default text)
  -o, --output <file>     Write report to file instead of stdout
      --fail-on <sev>     critical|high|medium|low|info|none (default: policy.failOn or high)
      --min-severity <s>  Hide findings below this level in text output
      --policy <file>     Policy file (default ./mcpscan.policy.json if present)
      --online            Check npm registry / GitHub for deprecated, stale, archived, missing packages
      --no-color          Disable ANSI colors
  -h, --help              Show help

Exit codes: 0 = no findings at/above --fail-on, 1 = findings, 2 = usage/runtime error.`;

function parseArgs(argv) {
  const o = { projects: [], extraConfigs: [], extraSkillDirs: [], toolsFiles: [], format: 'text', color: process.stdout.isTTY, defaultRoots: true };
  const cmds = ['scan', 'list', 'paths', 'rules', 'init-policy', 'mcp', 'help'];
  if (argv[0] && cmds.includes(argv[0])) o.cmd = argv.shift(); else o.cmd = 'scan';
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], v = () => { if (argv[i + 1] === undefined) throw new Error(`${a} needs a value`); return argv[++i]; };
    switch (a) {
      case '-p': case '--project': o.projects.push(v()); break;
      case '-c': case '--config': o.extraConfigs.push(v()); break;
      case '-s': case '--skills': o.extraSkillDirs.push(v()); break;
      case '-t': case '--tools': o.toolsFiles.push(v()); break;
      case '--root': { const r = v(); o.home = /^[A-Za-z]:[\\/]/.test(r) ? r : path.resolve(r); break; }
      case '--platform': o.platform = v(); break;
      case '--no-default-roots': o.defaultRoots = false; break;
      case '-f': case '--format': o.format = v(); break;
      case '-o': case '--output': o.output = v(); break;
      case '--fail-on': o.failOn = v(); break;
      case '--min-severity': o.minSeverity = v(); break;
      case '--policy': o.policyFile = v(); break;
      case '--online': o.online = true; break;
      case '--no-color': o.color = false; break;
      case '-h': case '--help': o.cmd = 'help'; break;
      default: throw new Error(`Unknown option: ${a}`);
    }
  }
  if (!['text', 'json', 'sarif', 'html'].includes(o.format)) throw new Error(`Unknown format: ${o.format}`);
  if (o.failOn && !['critical', 'high', 'medium', 'low', 'info', 'none'].includes(o.failOn)) throw new Error(`Bad --fail-on: ${o.failOn}`);
  if (!o.projects.length && o.defaultRoots) o.projects.push(process.cwd());
  return o;
}

async function main(argv) {
  let o;
  try { o = parseArgs(argv); } catch (e) { process.stderr.write(`mcpscan: ${e.message}\n\n${HELP}\n`); return 2; }
  if (o.cmd === 'help') { process.stdout.write(HELP + '\n'); return 0; }
  if (o.cmd === 'mcp') { require('../src/mcp-server').start(); return null; }
  if (o.cmd === 'rules') { for (const [id, r] of Object.entries(RULES)) console.log(`${id}  ${r.severity.padEnd(8)} ${r.name.padEnd(26)} ${r.title}`); return 0; }
  if (o.cmd === 'paths') { for (const c of configCandidates({ home: o.home, platform: o.platform })) console.log(`${c.client.padEnd(16)} ${c.file}`); return 0; }
  if (o.cmd === 'init-policy') {
    const dest = path.resolve('mcpscan.policy.json');
    if (fs.existsSync(dest)) { console.error('mcpscan.policy.json already exists'); return 2; }
    fs.copyFileSync(path.join(__dirname, '..', 'mcpscan.policy.json'), dest);
    console.log(`wrote ${dest}`); return 0;
  }
  if (o.cmd === 'list') {
    const d = discover(o);
    for (const c of d.configs) console.log(`config ${c.client}: ${c.file}\n  servers: ${c.servers.map(s => s.name).join(', ') || '(none)'}${c.error ? `\n  error: ${c.error}` : ''}`);
    for (const s of d.skills) console.log(`skill  ${s.source}: ${s.dir}`);
    if (!d.configs.length && !d.skills.length) console.log('Nothing found.');
    return 0;
  }
  try {
    const policy = loadPolicy(o.policyFile);
    const result = await scan({ ...o, policy });
    const out = render(result, o.format, { color: o.color && !o.output, minSeverity: o.minSeverity });
    if (o.output) { fs.writeFileSync(o.output, out); process.stderr.write(`wrote ${o.format} report to ${o.output} (${result.summary.findings} findings)\n`); }
    else process.stdout.write(out + '\n');
    return exitCodeFor(result, o.failOn || policy.failOn || 'high');
  } catch (e) {
    process.stderr.write(`mcpscan: ${e.message}\n`); return 2;
  }
}

main(process.argv.slice(2)).then(code => { if (code !== null) process.exitCode = code; });
