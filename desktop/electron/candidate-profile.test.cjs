const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { candidateEnvironment } = require('./candidate-profile.cjs');

test('candidate storage paths stay in its dedicated profile', () => {
  const root = path.resolve('netbot-candidate-fixture');
  const env = candidateEnvironment(root);
  for (const [key, value] of Object.entries(env)) {
    if (key.endsWith('_PATH') || key.endsWith('_DIR')) assert.ok(value.startsWith(root + path.sep));
  }
  assert.equal(env.NETBOT_JOURNAL_ACK_MODE, 'history');
  assert.equal(env.NETBOT_CAPTURE_MODE, 'metadata');
  assert.equal(env.NETBOT_STABILITY_RECORDING, '0');
});
test('candidate rejects relative and ordinary installed profiles', () => {
  for (const value of ['netbot-candidate-fixture', path.resolve('Netbotpro'), path.parse(process.cwd()).root]) {
    assert.throws(() => candidateEnvironment(value));
  }
});
