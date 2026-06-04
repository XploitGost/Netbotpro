import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const frontendRoot = process.cwd();
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
        index: "app.html",
      },
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.jsx"],
    root: frontendRoot,
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
