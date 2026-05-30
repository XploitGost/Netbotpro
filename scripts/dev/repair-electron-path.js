const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..", "..");
const electronDir = path.join(repoRoot, "desktop", "electron", "node_modules", "electron");
const distDir = path.join(electronDir, "dist");
const pathFile = path.join(electronDir, "path.txt");

const executableName =
  process.platform === "win32"
    ? "electron.exe"
    : process.platform === "darwin"
      ? "Electron.app/Contents/MacOS/Electron"
      : "electron";

const executablePath = path.join(distDir, ...executableName.split("/"));

if (!fs.existsSync(executablePath)) {
  console.error(
    [
      "Electron binary is missing from desktop/electron/node_modules/electron/dist.",
      "Run `npm install` in desktop/electron with a working Electron download cache, then retry `npm run dev`.",
      `Expected binary: ${executablePath}`,
    ].join("\n")
  );
  process.exit(1);
}

if (!fs.existsSync(pathFile)) {
  fs.writeFileSync(pathFile, executableName, "utf8");
}
