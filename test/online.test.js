'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
require('./helpers');
const { checkPackageLiveness, githubRepo } = require('../src/online');
const { scan } = require('../src/scan');
const path = require('path');
const { FIX } = require('./helpers');
const { DEFAULT_POLICY } = require('../src/policy');

// Mock registry: no real network is used.
const NOW = Date.parse('2026-10-15T00:00:00Z');
function mockFetch(routes) {
  return async url => {
    const r = routes[url];
    if (!r) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => r };
  };
}
const routes = {
  'https://registry.npmjs.org/old-pkg': { 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { version: '1.0.0', deprecated: 'use new-pkg', repository: { url: 'git+https://github.com/acme/old-pkg.git' } } }, time: { '1.0.0': '2023-01-01T00:00:00Z' } },
  'https://api.github.com/repos/acme/old-pkg': { archived: true },
  'https://registry.npmjs.org/fresh': { 'dist-tags': { latest: '2.0.0' }, versions: { '2.0.0': { version: '2.0.0' } }, time: { '2.0.0': '2026-09-01T00:00:00Z' } },
};

test('online: deprecated + stale + archived', async () => {
  const f = await checkPackageLiveness({ ecosystem: 'npm', name: 'old-pkg', version: null }, {}, { fetchImpl: mockFetch(routes), now: NOW });
  const ids = f.map(x => x.ruleId).sort();
  assert.deepEqual(ids, ['MCP013', 'MCP014', 'MCP015']);
});
test('online: missing package', async () => {
  const f = await checkPackageLiveness({ ecosystem: 'npm', name: 'no-such-pkg', version: null }, {}, { fetchImpl: mockFetch(routes), now: NOW });
  assert.equal(f[0].ruleId, 'MCP016');
});
test('online: fresh package is clean', async () => {
  assert.deepEqual(await checkPackageLiveness({ ecosystem: 'npm', name: 'fresh', version: '2.0.0' }, {}, { fetchImpl: mockFetch(routes), now: NOW }), []);
});
test('online: network failure is silent, not a crash', async () => {
  const f = await checkPackageLiveness({ ecosystem: 'npm', name: 'x', version: null }, {}, { fetchImpl: async () => { throw new Error('offline'); } });
  assert.deepEqual(f, []);
});
test('offline by default: scan never calls fetch', async () => {
  let called = 0;
  await scan({ home: path.join(FIX, 'home'), platform: 'linux', policy: DEFAULT_POLICY, fetchImpl: async () => { called++; throw new Error('x'); } });
  assert.equal(called, 0);
});
test('githubRepo parsing', () => assert.equal(githubRepo({ url: 'git+https://github.com/a/b.git' }), 'a/b'));
