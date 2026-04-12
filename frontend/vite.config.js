import fs from "fs";
import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const frontendRoot = fs.realpathSync(__dirname);
const devBackendPort = Number(process.env.NETBOT_DEV_BACKEND_PORT || process.env.NETBOT_PORT || 8765);
const devHttpBackend = `http://127.0.0.1:${devBackendPort}`;
const devWsBackend = `ws://127.0.0.1:${devBackendPort}`;

export default defineConfig({
  root: frontendRoot,
  base: "./",
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        index: path.resolve(frontendRoot, "app.html"),
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": devHttpBackend,
      "/ws": {
        target: devWsBackend,
        ws: true
      }
    }
  }
});
