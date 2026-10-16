'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { readJsonFile, isFile, isDir } = require('./util');

/**
 * Build the list of known MCP config locations for a platform.
 * Pure function (no fs access) so Windows/macOS layouts are testable anywhere.
 */
function configCandidates({ platform = process.platform, home = os.homedir(), env = process.env } = {}) {
  const P = platform === 'win32' ? path.win32 : path.posix;
  const appData = platform === 'win32'
    ? (env.APPDATA || P.join(home, 'AppData', 'Roaming'))
    : platform === 'darwin' ? P.join(home, 'Library', 'Application Support')
    : (env.XDG_CONFIG_HOME || P.join(home, '.config'));
  const c = [];
  const add = (client, file, kind = 'mcpServers') => c.push({ client, file, kind });
  add('Claude Desktop', P.join(appData, 'Claude', 'claude_desktop_config.json'));
  add('Claude Code', P.join(home, '.claude.json'), 'claudeCode');
  add('Claude Code', P.join(home, '.claude', 'settings.json'));
  add('Claude Code', P.join(home, '.claude', '.mcp.json'));
  add('Cursor', P.join(home, '.cursor', 'mcp.json'));
  for (const variant of ['Code', 'Code - Insiders', 'VSCodium']) {
    add('VS Code', P.join(appData, variant, 'User', 'mcp.json'), 'servers');
    add('VS Code', P.join(appData, variant, 'User', 'settings.json'), 'vscodeSettings');
  }
  add('Windsurf', P.join(home, '.codeium', 'windsurf', 'mcp_config.json'));
  add('Windsurf', P.join(appData, 'Windsurf', 'User', 'settings.json'), 'vscodeSettings');
  return c;
}

function projectConfigCandidates(projectDir, P = path) {
  return [
    { client: 'Project (.mcp.json)', file: P.join(projectDir, '.mcp.json'), kind: 'mcpServers' },
    { client: 'Cursor (project)', file: P.join(projectDir, '.cursor', 'mcp.json'), kind: 'mcpServers' },
    { client: 'VS Code (project)', file: P.join(projectDir, '.vscode', 'mcp.json'), kind: 'servers' },
    { client: 'Windsurf (project)', file: P.join(projectDir, '.windsurf', 'mcp.json'), kind: 'mcpServers' },
  ];
}

function skillRootCandidates({ platform = process.platform, home = os.homedir() } = {}) {
  const P = platform === 'win32' ? path.win32 : path.posix;
  return [
    { source: 'Claude Code user skills', dir: P.join(home, '.claude', 'skills') },
    { source: 'Claude Code plugins', dir: P.join(home, '.claude', 'plugins'), deep: true },
    { source: 'Cursor skills', dir: P.join(home, '.cursor', 'skills') },
    { source: 'Cursor skills', dir: P.join(home, '.cursor', 'skills-cursor') },
  ];
}

/** Extract server entries from a parsed config, by kind. */
function extractServers(json, kind) {
  const out = [];
  const take = (obj, scope) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [name, def] of Object.entries(obj)) {
      if (def && typeof def === 'object') out.push({ name, def, scope });
    }
  };
  if (!json || typeof json !== 'object') return out;
  if (kind === 'servers') { take(json.servers, 'servers'); take(json.mcpServers, 'mcpServers'); }
  else if (kind === 'vscodeSettings') { take(json.mcp && json.mcp.servers, 'mcp.servers'); take(json['mcp.servers'], 'mcp.servers'); }
  else if (kind === 'claudeCode') {
    take(json.mcpServers, 'user');
    if (json.projects && typeof json.projects === 'object') {
      for (const [proj, pdef] of Object.entries(json.projects)) take(pdef && pdef.mcpServers, `project:${proj}`);
    }
  } else { take(json.mcpServers, 'mcpServers'); take(json.servers, 'servers'); }
  return out;
}

function loadConfig(cand) {
  if (!isFile(cand.file)) return null;
  try {
    const json = readJsonFile(cand.file);
    return { ...cand, servers: extractServers(json, cand.kind), raw: json };
  } catch (e) {
    return { ...cand, servers: [], error: `Could not parse: ${e.message}` };
  }
}

const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist']);

/** Find skill folders (directories containing SKILL.md). Never follows symlinks. */
function findSkills(root, { deep = false, maxDepth = 6 } = {}) {
  const found = [];
  const walk = (dir, depth) => {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    if (entries.some(e => e.isFile() && e.name.toLowerCase() === 'skill.md')) { found.push(dir); return; }
    for (const e of entries) {
      if (e.isDirectory() && !e.isSymbolicLink() && !SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name), depth + 1);
    }
  };
  if (isDir(root)) walk(root, 0);
  return found;
}

/**
 * Discover configs and skills.
 * opts: { home, platform, env, projects: [dirs], defaultRoots: bool, extraConfigs: [files], extraSkillDirs: [dirs] }
 */
function discover(opts = {}) {
  const home = opts.home || os.homedir();
  const platform = opts.platform || process.platform;
  const env = opts.env || (opts.home ? {} : process.env);
  const cands = [];
  if (opts.defaultRoots !== false) cands.push(...configCandidates({ platform, home, env }));
  for (const p of opts.projects || []) cands.push(...projectConfigCandidates(path.resolve(p)));
  for (const f of opts.extraConfigs || []) cands.push({ client: 'Explicit', file: path.resolve(f), kind: 'auto' });

  const seen = new Set();
  const configs = [];
  const checked = [];
  for (const c of cands) {
    const key = path.resolve(c.file);
    if (seen.has(key)) continue;
    seen.add(key);
    checked.push(c.file);
    const loaded = loadConfig(c);
    if (loaded) configs.push(loaded);
  }

  const skillRoots = [];
  if (opts.defaultRoots !== false) skillRoots.push(...skillRootCandidates({ platform, home }));
  for (const p of opts.projects || []) skillRoots.push({ source: 'Project skills', dir: path.join(path.resolve(p), '.claude', 'skills') });
  for (const d of opts.extraSkillDirs || []) skillRoots.push({ source: 'Explicit', dir: path.resolve(d), deep: true });
  const skills = [];
  const seenSkills = new Set();
  for (const r of skillRoots) {
    for (const dir of findSkills(r.dir, { deep: r.deep })) {
      if (seenSkills.has(dir)) continue;
      seenSkills.add(dir);
      skills.push({ source: r.source, dir, name: path.basename(dir) });
    }
  }
  return { configs, skills, checkedConfigPaths: checked, skillRoots: skillRoots.map(r => r.dir) };
}

module.exports = { discover, configCandidates, projectConfigCandidates, skillRootCandidates, extractServers, findSkills };
