'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { execFileSync, spawnSync } = require('child_process');
const { FIX } = require('./helpers');
const { scan, exitCodeFor } = require('../src/scan');
const { DEFAULT_POLICY, loadPolicy, applyPolicy, match } = require('../src/policy');
const { render } = require('../src/report');
const { RULES } = require('../src/rules');

const FAKE = ['ghp_' + 'FAKE0TEST0TOKEN0DO0NOT0USE0000000000', 'sk-ant-' + 'api03-FAKEFAKEFAKEFAKEFAKEFAKE0000', 'AKIA' + 'FAKEFAKEFAKE1234', 'hunter2pass'];
const base = { home: path.join(FIX, 'home'), platform: 'linux', projects: [path.join(FIX, 'project')], toolsFiles: [path.join(FIX, 'tools-poisoned.json')] };
let cached;
const full = async () => cached || (cached = await scan({ ...base, policy: loadPolicy(path.join(__dirname, '..', 'mcpscan.policy.json')) }));

test('full fixture scan covers every offline rule', async () => {
  const r = await full();
  const got = new Set(r.findings.map(f => f.ruleId));
  for (const id of ['MCP001', 'MCP002', 'MCP003', 'MCP004', 'MCP005', 'MCP006', 'MCP007', 'MCP008', 'MCP009', 'MCP010', 'MCP011', 'MCP017']) assert.ok(got.has(id), id);
});
test('good-skill has no findings', async () => {
  const r = await full();
  assert.equal(r.skills.find(s => s.name === 'good-skill').findingCount, 0);
});
test('no full secret value appears in any report format', async () => {
  const r = await full();
  for (const fmt of ['text', 'json', 'sarif', 'html']) {
    const out = render(r, fmt);
    for (const s of FAKE) assert.ok(!out.includes(s), `${fmt} leaked ${s.slice(0, 4)}`);
  }
});
test('SARIF 2.1.0 structure', async () => {
  const s = JSON.parse(render(await full(), 'sarif'));
  assert.equal(s.version, '2.1.0');
  assert.equal(s.runs[0].tool.driver.rules.length, Object.keys(RULES).length);
  assert.ok(s.runs[0].results.every(x => ['error', 'warning', 'note'].includes(x.level)));
  assert.ok(s.runs[0].results.some(x => x.locations[0] && x.locations[0].physicalLocation.artifactLocation.uri.startsWith('file:///')));
});
test('HTML escapes untrusted content', async () => {
  const h = render(await full(), 'html');
  assert.ok(h.startsWith('<!doctype html>'));
  assert.ok(!h.includes('<IMPORTANT>'), 'raw tag from fixture must be escaped');
  assert.ok(h.includes('&lt;IMPORTANT&gt;'));
});
test('JSON report has summary counts', async () => {
  const j = JSON.parse(render(await full(), 'json'));
  const sum = Object.values(j.summary.counts).reduce((a, b) => a + b, 0);
  assert.equal(sum, j.findings.length);
});
test('policy: deny host and package', async () => {
  const r = await full();
  assert.ok(r.findings.some(f => f.ruleId === 'MCP011' && /ngrok/.test(f.message)));
  assert.ok(r.findings.some(f => f.ruleId === 'MCP011' && /stripe-mcp-free-tools/.test(f.message)));
});
test('policy: requireAllowList flags unlisted servers, allows listed', async () => {
  const policy = { ...DEFAULT_POLICY, requireAllowList: true, allow: { ...DEFAULT_POLICY.allow, packages: ['@modelcontextprotocol/*'], hosts: ['mcp.linear.app'], skills: ['tidy'] } };
  const r = await scan({ home: base.home, defaultRoots: false, projects: [path.join(FIX, 'clean')], policy });
  assert.equal(r.findings.filter(f => f.ruleId === 'MCP012').length, 0);
  const r2 = await scan({ home: base.home, defaultRoots: false, projects: [path.join(FIX, 'project')], policy });
  assert.ok(r2.findings.some(f => f.ruleId === 'MCP012'));
});
test('policy: ignore and severity override', () => {
  const f = [{ ruleId: 'MCP008', rule: 'unpinned-package', severity: 'medium', target: 'x' }, { ruleId: 'MCP009', rule: 'insecure-transport', severity: 'high', target: 'y' }];
  const out = applyPolicy({ ...DEFAULT_POLICY, ignore: [{ rule: 'MCP008', target: 'x' }], severityOverrides: { MCP009: 'low' } }, f);
  assert.equal(out.length, 1); assert.equal(out[0].severity, 'low');
  assert.ok(match('@modelcontextprotocol/*', '@modelcontextprotocol/server-git'));
});
test('skill missing frontmatter reported without policy ignore', async () => {
  const r = await scan({ ...base, policy: { ...DEFAULT_POLICY } });
  assert.ok(r.findings.some(f => f.ruleId === 'MCP018'));
});
test('exit codes: findings -> 1, clean -> 0, fail-on none -> 0', async () => {
  assert.equal(exitCodeFor(await full(), 'high'), 1);
  assert.equal(exitCodeFor(await full(), 'none'), 0);
  const clean = await scan({ home: base.home, defaultRoots: false, projects: [path.join(FIX, 'clean')], policy: { ...DEFAULT_POLICY } });
  assert.equal(clean.findings.length, 0);
  assert.equal(exitCodeFor(clean, 'info'), 0);
});

const CLI = path.join(__dirname, '..', 'bin', 'mcpscan.js');
const run = args => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', cwd: path.join(__dirname, '..') });
test('CLI: exit 1 on fixtures, 0 on clean, 2 on bad args', () => {
  assert.equal(run(['--root', base.home, '--platform', 'linux', '-p', base.projects[0], '--no-color']).status, 1);
  assert.equal(run(['--no-default-roots', '-p', path.join(FIX, 'clean')]).status, 0);
  assert.equal(run(['--bogus']).status, 2);
  assert.equal(run(['--format', 'pdf']).status, 2);
});
test('CLI: writes each report format to file', () => {
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'mcpscan-'));
  for (const fmt of ['json', 'sarif', 'html', 'text']) {
    const out = path.join(tmp, `r.${fmt}`);
    const p = run(['--root', base.home, '--platform', 'linux', '-p', base.projects[0], '-f', fmt, '-o', out, '--fail-on', 'none']);
    assert.equal(p.status, 0, p.stderr);
    assert.ok(fs.statSync(out).size > 200);
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});
test('CLI: rules, paths, list, help', () => {
  assert.match(run(['rules']).stdout, /MCP001/);
  assert.match(run(['paths', '--root', 'C:\\Users\\K', '--platform', 'win32']).stdout, /AppData\\Roaming\\Claude/);
  assert.match(run(['list', '--no-default-roots', '-p', path.join(FIX, 'clean')]).stdout, /memory/);
  assert.equal(run(['--help']).status, 0);
});
