'use strict';
/** Rule catalog. id -> metadata. Severity: critical | high | medium | low | info */
const RULES = {
  'MCP001': { name: 'prompt-injection', severity: 'high', title: 'Prompt-injection / hidden instruction pattern' },
  'MCP002': { name: 'hidden-unicode', severity: 'high', title: 'Invisible or bidirectional Unicode characters' },
  'MCP003': { name: 'exfiltration', severity: 'critical', title: 'Instruction to exfiltrate data or conceal actions' },
  'MCP004': { name: 'dangerous-command', severity: 'high', title: 'Dangerous shell command' },
  'MCP005': { name: 'credential-path', severity: 'high', title: 'Access to credential / secret file paths' },
  'MCP006': { name: 'encoded-payload', severity: 'medium', title: 'Large base64/encoded blob' },
  'MCP007': { name: 'hardcoded-secret', severity: 'high', title: 'Hardcoded secret in config or file' },
  'MCP008': { name: 'unpinned-package', severity: 'medium', title: 'Unpinned package version' },
  'MCP009': { name: 'insecure-transport', severity: 'high', title: 'Plain-HTTP remote MCP transport' },
  'MCP010': { name: 'excessive-fs-root', severity: 'high', title: 'Excessive filesystem root granted' },
  'MCP011': { name: 'policy-deny', severity: 'high', title: 'Denied by policy' },
  'MCP012': { name: 'policy-not-allowed', severity: 'medium', title: 'Not on policy allow list' },
  'MCP013': { name: 'package-deprecated', severity: 'high', title: 'Package deprecated on npm' },
  'MCP014': { name: 'package-stale', severity: 'low', title: 'Package not published in a long time' },
  'MCP015': { name: 'repo-archived', severity: 'medium', title: 'Source repository archived' },
  'MCP016': { name: 'package-missing', severity: 'high', title: 'Package not found in registry (dead or typo-squat risk)' },
  'MCP017': { name: 'config-parse-error', severity: 'low', title: 'Config file could not be parsed' },
  'MCP018': { name: 'skill-missing-frontmatter', severity: 'info', title: 'SKILL.md missing name/description frontmatter' },
};
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const sevRank = s => SEVERITIES.indexOf(s);
module.exports = { RULES, SEVERITIES, sevRank };
