'use strict';
const path = require('path');
const FIX = path.join(__dirname, 'fixtures');
// Never allow network in tests.
globalThis.fetch = async () => { throw new Error('network disabled in tests'); };
const ids = fs => fs.map(f => f.ruleId);
module.exports = { FIX, ids };
