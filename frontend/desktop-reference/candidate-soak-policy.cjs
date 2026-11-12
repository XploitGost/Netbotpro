const path = require('node:path');

function validateSoakPolicy({ root, cwd, grant, nonce, duration }) {
  if (!path.isAbsolute(root) || path.resolve(root) !== path.resolve(cwd) || !path.basename(root).startsWith('netbot-candidate-soak-')) {
    throw new Error('Long capture requires its supervised scratch workspace');
  }
  if (grant.version !== 1 || !nonce || nonce !== grant.nonce || grant.durationSeconds !== duration ||
      !Number.isInteger(duration) || duration < 300 || duration > 1800 || grant.maxProfileBytes !== 512 * 1024**2 ||
      typeof grant.requireVpnCycle !== 'boolean') {
    throw new Error('Invalid supervised soak policy');
  }
  return grant;
}
module.exports = { validateSoakPolicy };
