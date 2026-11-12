import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vite = path.join(frontend, "node_modules/vite/bin/vite.js");
if (!fs.existsSync(vite)) throw new Error("Install frontend dependencies with npm ci in frontend first.");
const result = spawnSync(process.execPath, [vite, "build"], { cwd: frontend, stdio: "inherit" });
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
