'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { FIX } = require('./helpers');
const { discover, configCandidates, skillRootCandidates } = require('../src/discover');

test('windows candidate paths use %APPDATA% and %USERPROFILE%', () => {
  const c = configCandidates({ platform: 'win32', home: 'C:\\Users\\Kurt', env: { APPDATA: 'C:\\Users\\Kurt\\AppData\\Roaming' } }).map(x => x.file);
  assert.ok(c.includes('C:\\Users\\Kurt\\AppData\\Roaming\\Claude\\claude_desktop_config.json'));
  assert.ok(c.includes('C:\\Users\\Kurt\\.cursor\\mcp.json'));
  assert.ok(c.includes('C:\\Users\\Kurt\\.claude.json'));
  assert.ok(c.includes('C:\\Users\\Kurt\\AppData\\Roaming\\Code\\User\\mcp.json'));
  assert.ok(c.includes('C:\\Users\\Kurt\\.codeium\\windsurf\\mcp_config.json'));
  assert.ok(skillRootCandidates({ platform: 'win32', home: 'C:\\Users\\Kurt' }).some(s => s.dir === 'C:\\Users\\Kurt\\.claude\\skills'));
});
test('windows APPDATA fallback when env missing', () => {
  const c = configCandidates({ platform: 'win32', home: 'C:\\Users\\K', env: {} }).map(x => x.file);
  assert.ok(c.includes('C:\\Users\\K\\AppData\\Roaming\\Claude\\claude_desktop_config.json'));
});
test('macOS candidate paths use Library/Application Support', () => {
  const c = configCandidates({ platform: 'darwin', home: '/Users/k', env: {} }).map(x => x.file);
  assert.ok(c.includes('/Users/k/Library/Application Support/Claude/claude_desktop_config.json'));
  assert.ok(c.includes('/Users/k/Library/Application Support/Code/User/mcp.json'));
});
test('linux candidate paths use ~/.config', () => {
  const c = configCandidates({ platform: 'linux', home: '/home/k', env: {} }).map(x => x.file);
  assert.ok(c.includes('/home/k/.config/Claude/claude_desktop_config.json'));
});
test('discovers every client config and skill in fixtures', () => {
  const d = discover({ home: path.join(FIX, 'home'), platform: 'linux', projects: [path.join(FIX, 'project')] });
  const clients = new Set(d.configs.map(c => c.client));
  for (const c of ['Claude Desktop', 'Claude Code', 'Cursor', 'VS Code', 'Windsurf', 'Project (.mcp.json)', 'VS Code (project)']) assert.ok(clients.has(c), c);
  const names = d.skills.map(s => s.name);
  for (const s of ['good-skill', 'injection-skill', 'unicode-skill', 'exfil-skill', 'secret-skill', 'plugin-skill', 'proj-skill']) assert.ok(names.includes(s), s);
  const cc = d.configs.find(c => c.file.endsWith('.claude.json'));
  assert.ok(cc.servers.some(s => s.scope === 'project:/work/app'), 'Claude Code per-project servers');
  assert.ok(d.configs.find(c => c.client === 'Windsurf').error, 'broken JSON reported');
});
test('no-default-roots only scans given project', () => {
  const d = discover({ home: path.join(FIX, 'home'), defaultRoots: false, projects: [path.join(FIX, 'clean')] });
  assert.equal(d.configs.length, 1); assert.equal(d.skills.length, 1);
});
