import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";

process.chdir(realpathSync(process.cwd()));

const command = process.platform === "win32" ? "npx.cmd" : "npx";
const result = spawnSync(command, ["vitest", "run"], {
  stdio: "inherit",
});

process.exit(result.status ?? 1);
