function frontendEntry(env = process.env) {
  const mode = String(env.NETBOT_DESKTOP_UI || "standard").trim().toLowerCase() || "standard";
  if (mode === "standard") return "app.html";
  if (mode === "desktop") return "desktop.html";
  throw new Error("NETBOT_DESKTOP_UI must be standard or desktop");
}

module.exports = { frontendEntry };
