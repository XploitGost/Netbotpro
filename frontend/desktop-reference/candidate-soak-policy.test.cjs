const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { validateSoakPolicy } = require('./candidate-soak-policy.cjs');

const root = path.resolve('netbot-candidate-soak-fixture');
const grant = { version: 1, nonce: 'fixture-nonce', durationSeconds: 900, maxProfileBytes: 512 * 1024**2, requireVpnCycle: true };
const fixture = () => ({ root, cwd: root, grant: { ...grant }, nonce: grant.nonce, duration: 900 });
test('explicit supervisor grant permits only the bounded longer mode', () => {
  assert.equal(validateSoakPolicy(fixture()).durationSeconds, 900);
});
test('ordinary or mismatched workspaces cannot enable long capture', () => {
  for (const change of [{ root: 'relative' }, { cwd: path.dirname(root) }, { root: path.resolve('ordinary'), cwd: path.resolve('ordinary') }]) {
    assert.throws(() => validateSoakPolicy({ ...fixture(), ...change }));
  }
});
test('duration, nonce and storage limits cannot silently expand', () => {
  for (const change of [{ nonce: 'wrong' }, { duration: 7200 }, { duration: 120 },
    { grant: { ...grant, maxProfileBytes: 1024**3 } }, { grant: { ...grant, requireVpnCycle: 'yes' } }]) {
    assert.throws(() => validateSoakPolicy({ ...fixture(), ...change }));
  }
});
