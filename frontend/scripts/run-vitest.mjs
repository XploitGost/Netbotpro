import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { join } from "node:path";

process.chdir(realpathSync(process.cwd()));

const vitestBin = join(process.cwd(), "node_modules", "vitest", "vitest.mjs");
const result = spawnSync(process.execPath, [vitestBin, "run"], {
  stdio: "inherit",
});

if (result.error) {
  console.error(result.error.message);
}

process.exit(result.status ?? 1);
