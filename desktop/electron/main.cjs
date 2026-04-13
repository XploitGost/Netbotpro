const { app, BrowserWindow, Menu, dialog, ipcMain, shell } = require("electron");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const BACKEND_PORT = Number(process.env.NETBOT_PORT || 8765);
const BACKEND_HOST = process.env.NETBOT_HOST || "127.0.0.1";
const BACKEND_BASE_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}`;

let mainWindow = null;
let backendProcess = null;
let shuttingDown = false;
let desktopLocalToken = "";

function isPackagedApp() {
  return app.isPackaged;
}

function repoRoot() {
  return path.resolve(__dirname, "..", "..");
}

function desktopPaths() {
  const userData = app.getPath("userData");
  const configDir = path.join(userData, "config");
  const dataDir = path.join(userData, "data");
  const logDir = path.join(userData, "logs");
  [configDir, dataDir, logDir].forEach((dir) => fs.mkdirSync(dir, { recursive: true }));
  return { userData, configDir, dataDir, logDir };
}

function createMenu() {
  const template = [
    {
      label: "Netbotpro",
      submenu: [
        {
          label: "Reload",
          click: () => mainWindow?.reload(),
        },
        {
          label: "Quit",
          click: () => app.quit(),
        },
      ],
    },
    {
      label: "View",
      submenu: [
        { role: "toggleDevTools" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { role: "togglefullscreen" },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function managedLocalToken() {
  const configured = String(process.env.NETBOT_LOCAL_TOKEN || "").trim();
  if (configured) {
    desktopLocalToken = configured;
    return desktopLocalToken;
  }
  if (!desktopLocalToken) {
    desktopLocalToken = crypto.randomBytes(32).toString("hex");
  }
  return desktopLocalToken;
}

function runtimeConfig() {
  return {
    apiBase: `${BACKEND_BASE_URL}/api`,
    wsBase: `ws://${BACKEND_HOST}:${BACKEND_PORT}/ws`,
    platform: process.platform,
    localToken: managedLocalToken(),
    managedLocalToken: true,
  };
}

function parseDesktopUrl(target) {
  try {
    return new URL(target);
  } catch (_error) {
    return null;
  }
}

function isAllowedDesktopUrl(target) {
  const parsed = parseDesktopUrl(target);
  if (!parsed) {
    return false;
  }
  if (parsed.protocol === "file:") {
    return true;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return false;
  }
  return ["127.0.0.1", "localhost"].includes(parsed.hostname);
}

function openExternalIfSafe(target) {
  const parsed = parseDesktopUrl(target);
  if (parsed && ["http:", "https:"].includes(parsed.protocol)) {
    void shell.openExternal(target);
  }
}

function hardenWindow(window) {
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedDesktopUrl(url)) {
      return { action: "allow" };
    }
    openExternalIfSafe(url);
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, url) => {
    if (isAllowedDesktopUrl(url)) {
      return;
    }
    event.preventDefault();
    openExternalIfSafe(url);
  });
}

function registerRuntimeBridge() {
  ipcMain.on("netbotpro:get-runtime-config", (event) => {
    event.returnValue = runtimeConfig();
  });
}

function resolveBackendLaunch(paths) {
  const envOverride = process.env.NETBOT_BACKEND_BIN;
  if (envOverride) {
    return {
      command: envOverride,
      args: [],
      cwd: path.dirname(envOverride),
      env: backendEnv(paths),
    };
  }

  const packagedBinary = path.join(process.resourcesPath, "runtime", "backend", process.platform === "win32" ? "netbotpro-backend.exe" : "netbotpro-backend");
  if (isPackagedApp() && fs.existsSync(packagedBinary)) {
    return {
      command: packagedBinary,
      args: [],
      cwd: path.dirname(packagedBinary),
      env: backendEnv(paths),
    };
  }

  const pythonBin = process.env.NETBOT_PYTHON_BIN || (process.platform === "win32" ? "python" : "python3");
  const sourceRoot = isPackagedApp() ? path.join(process.resourcesPath, "python-src") : repoRoot();
  return {
    command: pythonBin,
    args: ["-m", "backend.app.desktop_entry"],
    cwd: sourceRoot,
    env: {
      ...backendEnv(paths),
      PYTHONPATH: [sourceRoot, process.env.PYTHONPATH || ""].filter(Boolean).join(path.delimiter),
    },
  };
}

function backendEnv(paths) {
  return {
    ...process.env,
    NETBOT_PORT: String(BACKEND_PORT),
    NETBOT_HOST: BACKEND_HOST,
    NETBOT_LOCAL_TOKEN: managedLocalToken(),
    NETBOT_CONFIG_DIR: paths.configDir,
    NETBOT_DATA_DIR: paths.dataDir,
    NETBOT_LOG_DIR: paths.logDir,
    NETBOT_ALLOWED_ORIGINS: "http://127.0.0.1:5173,http://localhost:5173,null,file://",
  };
}

async function waitForBackend(timeoutMs = 20000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(`${BACKEND_BASE_URL}/api/status`);
      if (response.ok) {
        return true;
      }
    } catch (_error) {
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}

async function startBackend(paths) {
  if (backendProcess) {
    return;
  }
  const launch = resolveBackendLaunch(paths);
  backendProcess = spawn(launch.command, launch.args, {
    cwd: launch.cwd,
    env: launch.env,
    stdio: "pipe",
    windowsHide: true,
  });

  backendProcess.on("exit", async (code) => {
    const crashed = !shuttingDown && code !== 0;
    backendProcess = null;
    if (crashed) {
      await dialog.showErrorBox("Netbotpro Backend", `Backend process exited with code ${code}.`);
    }
  });
}

async function stopBackend() {
  if (!backendProcess) {
    return;
  }
  const child = backendProcess;
  backendProcess = null;
  child.kill();
}

async function createWindow() {
  const paths = desktopPaths();
  createMenu();
  await startBackend(paths);
  const healthy = await waitForBackend();
  if (!healthy) {
    await dialog.showErrorBox("Netbotpro Backend", "Backend health check failed. See desktop logs for details.");
  }

  mainWindow = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 1100,
    minHeight: 760,
    title: "Netbotpro",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });
  hardenWindow(mainWindow);

  const devUrl = process.env.NETBOT_DESKTOP_DEV_SERVER_URL;
  if (!isPackagedApp() && devUrl) {
    if (!isAllowedDesktopUrl(devUrl)) {
      throw new Error("NETBOT_DESKTOP_DEV_SERVER_URL must point to a loopback URL");
    }
    await mainWindow.loadURL(devUrl);
  } else {
    await mainWindow.loadFile(path.join(isPackagedApp() ? process.resourcesPath : repoRoot(), isPackagedApp() ? "frontend" : path.join("frontend", "dist"), "app.html"));
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function setupAppLifecycle() {
  app.on("window-all-closed", async () => {
    if (process.platform !== "darwin") {
      shuttingDown = true;
      await stopBackend();
      app.quit();
    }
  });

  app.on("before-quit", async () => {
    shuttingDown = true;
    await stopBackend();
  });

  app.on("activate", async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createWindow();
    }
  });
}

async function bootstrap() {
  const lock = app.requestSingleInstanceLock();
  if (!lock) {
    app.quit();
    return;
  }
  setupAppLifecycle();
  registerRuntimeBridge();
  await app.whenReady();
  await createWindow();
}

bootstrap();
