const { app } = require("electron");
const fs = require("node:fs");
const path = require("node:path");

const profile = process.env.NETBOT_SMOKE_USER_DATA;
if (!profile) throw new Error("A dedicated smoke-test profile is required");
fs.mkdirSync(profile, { recursive: true });
app.setPath("userData", profile);
app.setName("NetBotPro Runtime Smoke");
app.on("browser-window-created", (_event, window) => window.on("show", () => window.hide()));
require(path.resolve(__dirname, "../../desktop/electron/main.cjs"));
