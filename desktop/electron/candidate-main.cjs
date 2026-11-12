const { app } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { candidateEnvironment, candidatePort } = require('./candidate-profile.cjs');

const profile = process.env.NETBOT_CANDIDATE_PROFILE || path.join(app.getPath('appData'), 'netbot-candidate-preview');
Object.assign(process.env, candidateEnvironment(profile));
// Candidate packages must not silently run an inherited, older backend or dev URL.
delete process.env.NETBOT_BACKEND_BIN;
delete process.env.NETBOT_PYTHON_BIN;
delete process.env.NETBOT_DESKTOP_DEV_SERVER_URL;
app.setPath('userData', profile);
app.setName('NetBotPro Candidate');
const config = path.join(profile, 'config');
fs.mkdirSync(config, { recursive: true });
const settings = path.join(config, 'settings.json');
if (!fs.existsSync(settings)) {
  fs.writeFileSync(settings, JSON.stringify({ iface: 'iface=default', autostart_sniffer: false,
    auto_block: false, persist_logs: true, retention_minutes: 15, sniffer_sample_rate: 1,
    payload_capture_enabled: false, capture_mode: 'metadata' }));
}
// Resolve a loopback port before main.cjs snapshots its backend configuration.
const reservation = net.createServer();
reservation.on('error', error => { throw error; });
reservation.listen(candidatePort(process.env.NETBOT_CANDIDATE_PORT), '127.0.0.1', () => {
  const port = reservation.address().port;
  reservation.close(() => {
    process.env.NETBOT_PORT = String(port);
    require('./main.cjs');
  });
});
