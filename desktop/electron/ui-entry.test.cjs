const assert = require("node:assert/strict");
const { test } = require("node:test");
const { frontendEntry } = require("./ui-entry.cjs");

test("standard entry remains default and desktop is explicit", () => {
  assert.equal(frontendEntry({}), "app.html");
  assert.equal(frontendEntry({ NETBOT_DESKTOP_UI: "desktop" }), "desktop.html");
  assert.equal(frontendEntry({ NETBOT_DESKTOP_UI: " STANDARD " }), "app.html");
});

test("entry setting cannot become an arbitrary file or URL", () => {
  for (const value of ["../secret.html", "https://example.test", "file:///etc/passwd", "unknown"]) {
    assert.throws(() => frontendEntry({ NETBOT_DESKTOP_UI: value }));
  }
});
