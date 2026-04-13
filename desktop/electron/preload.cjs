const { contextBridge, ipcRenderer } = require("electron");

function readRuntimeConfig() {
  try {
    return ipcRenderer.sendSync("netbotpro:get-runtime-config") || {};
  } catch (_error) {
    return {};
  }
}

contextBridge.exposeInMainWorld("netbotproDesktop", Object.freeze(readRuntimeConfig()));
