const { contextBridge, ipcRenderer } = require("electron");

function readAdditionalArgumentConfig() {
  const prefix = "--netbot-runtime-config=";
  const raw = (process.argv || []).find((item) => String(item).startsWith(prefix));
  if (!raw) {
    return {};
  }
  try {
    const encoded = String(raw).slice(prefix.length);
    const decoded = Buffer.from(encoded, "base64url").toString("utf8");
    return JSON.parse(decoded) || {};
  } catch (_error) {
    return {};
  }
}

function readRuntimeConfig() {
  try {
    return ipcRenderer.sendSync("netbotpro:get-runtime-config") || {};
  } catch (_error) {
    return readAdditionalArgumentConfig();
  }
}

contextBridge.exposeInMainWorld("netbotproDesktop", Object.freeze(readRuntimeConfig()));
