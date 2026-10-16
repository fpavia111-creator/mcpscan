'use strict';
const path = require('path');
const { readJsonFile, isFile } = require('./util');
const { finding } = require('./checks');
const { RULES } = require('./rules');

const DEFAULT_POLICY = { version: 1, failOn: 'high', allow: { servers: [], packages: [], hosts: [], skills: [] }, deny: { servers: [], packages: [], hosts: [], skills: [] }, ignore: [], severityOverrides: {}, requireAllowList: false };

function loadPolicy(file) {
  if (!file) {
    const local = path.resolve('mcpscan.policy.json');
    if (!isFile(local)) return { ...DEFAULT_POLICY, source: null };
    file = local;
  }
  const p = readJsonFile(file);
  return { ...DEFAULT_POLICY, ...p, allow: { ...DEFAULT_POLICY.allow, ...(p.allow || {}) }, deny: { ...DEFAULT_POLICY.deny, ...(p.deny || {}) }, source: path.resolve(file) };
}

/** Glob with * wildcard, case-insensitive. */
function match(pattern, value) {
  if (!value) return false;
  const re = new RegExp('^' + String(pattern).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
  return re.test(value);
}
const anyMatch = (list, v) => (list || []).some(p => match(p, v));

/** Policy checks for one server: identity = {name, package, host}. */
function checkServerPolicy(policy, ident, ctx) {
  const out = [];
  const c = { ...ctx, target: ident.name };
  const hit = (kind, v) => v && anyMatch(policy.deny[kind], v);
  if (hit('servers', ident.name)) out.push(finding('MCP011', { ...c, message: `Server name "${ident.name}" is on the deny list` }));
  if (hit('packages', ident.package)) out.push(finding('MCP011', { ...c, message: `Package "${ident.package}" is on the deny list`, evidence: ident.package }));
  if (hit('hosts', ident.host)) out.push(finding('MCP011', { ...c, message: `Host "${ident.host}" is on the deny list`, evidence: ident.host }));
  const allowed = anyMatch(policy.allow.servers, ident.name) || anyMatch(policy.allow.packages, ident.package) || anyMatch(policy.allow.hosts, ident.host);
  if (policy.requireAllowList && !allowed) out.push(finding('MCP012', { ...c, message: `Server "${ident.name}" is not on the allow list (requireAllowList=true)` }));
  return { findings: out, allowed };
}

function checkSkillPolicy(policy, name, ctx) {
  const c = { ...ctx, target: name };
  if (anyMatch(policy.deny.skills, name)) return { findings: [finding('MCP011', { ...c, message: `Skill "${name}" is on the deny list` })], allowed: false };
  const allowed = anyMatch(policy.allow.skills, name);
  if (policy.requireAllowList && !allowed) return { findings: [finding('MCP012', { ...c, message: `Skill "${name}" is not on the allow list` })], allowed };
  return { findings: [], allowed };
}

/** Apply ignore rules and severity overrides. ignore entries: {rule, target?, file?} or "MCP008". */
function applyPolicy(policy, findings) {
  return findings.filter(f => !(policy.ignore || []).some(ig => {
    if (typeof ig === 'string') return ig === f.ruleId || ig === f.rule;
    return (!ig.rule || ig.rule === f.ruleId || ig.rule === f.rule) && (!ig.target || match(ig.target, f.target)) && (!ig.file || match(ig.file, f.file));
  })).map(f => {
    const o = (policy.severityOverrides || {})[f.ruleId] || (policy.severityOverrides || {})[f.rule];
    return o && RULES[f.ruleId] ? { ...f, severity: o } : f;
  });
}

module.exports = { loadPolicy, checkServerPolicy, checkSkillPolicy, applyPolicy, match, DEFAULT_POLICY };
