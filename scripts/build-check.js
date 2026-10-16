'use strict';
// "Build" for a zero-dependency CLI: syntax-check every source file and load the modules.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
let n = 0;
for (const dir of ['bin', 'src', 'scripts', 'test']) {
  for (const f of fs.readdirSync(path.join(root, dir))) {
    if (!f.endsWith('.js')) continue;
    execFileSync(process.execPath, ['--check', path.join(root, dir, f)]);
    n++;
  }
}
require('../src/index');
JSON.parse(fs.readFileSync(path.join(root, 'mcpscan.policy.json'), 'utf8'));
console.log(`build ok: ${n} files syntax-checked, modules load, policy JSON valid`);
