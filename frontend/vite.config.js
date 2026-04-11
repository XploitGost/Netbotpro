import fs from "fs";
import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const frontendRoot = fs.realpathSync(__dirname);

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
      "/api": "http://127.0.0.1:8000",
      "/ws": {
        target: "ws://127.0.0.1:8000",
        ws: true
      }
    }
  }
});
