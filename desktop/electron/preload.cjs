const { contextBridge } = require("electron");

function readRuntimeConfig() {
  const arg = process.argv.find((item) => item.startsWith("--netbotpro-runtime="));
  if (!arg) {
    return {};
  }
  try {
    return JSON.parse(decodeURIComponent(arg.slice("--netbotpro-runtime=".length)));
  } catch (_error) {
    return {};
  }
}

contextBridge.exposeInMainWorld("netbotproDesktop", readRuntimeConfig());
