const path = require('node:path');

function candidateEnvironment(profile) {
  if (!path.isAbsolute(profile) || !path.basename(profile).startsWith('netbot-candidate-')) {
    throw new Error('Candidate profile must be an absolute, explicitly named netbot-candidate-* directory');
  }
  return {
    NETBOT_DESKTOP_UI: 'desktop', NETBOT_CAPTURE_MODE: 'metadata', NETBOT_HOST: '127.0.0.1', NETBOT_PROFILE: 'desktop',
    NETBOT_CAPTURE_PROCESS: '1', NETBOT_CAPTURE_JOURNAL: '1', NETBOT_JOURNAL_ACK_MODE: 'history',
    NETBOT_PAYLOAD_CAPTURE: '0', NETBOT_ALLOW_FULL_CAPTURE: '0', NETBOT_REDACT_SENSITIVE_DATA: '1',
    NETBOT_STABILITY_RECORDING: '0', NETBOT_PROFILE_STAGES: '0',
    NETBOT_DB_PATH: path.join(profile, 'data', 'history.db'),
    NETBOT_FLOW_DB_PATH: path.join(profile, 'data', 'flows.db'),
    NETBOT_CAPTURE_JOURNAL_PATH: path.join(profile, 'data', 'journal.db'),
    NETBOT_RUNTIME_DIR: path.join(profile, 'runtime'), NETBOT_CACHE_DIR: path.join(profile, 'cache'),
  };
}
module.exports = { candidateEnvironment };
