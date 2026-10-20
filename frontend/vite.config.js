import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  resolve: { dedupe: ['react','react-dom'] },
  server: { proxy: { "/api": "http://127.0.0.1:8110" } },
  // Bound simultaneous 64-MiB KDF tests and jsdom processes on development machines.
  test: { environment: "jsdom", setupFiles: ["./src/test-setup.js"], maxWorkers: 4 },
});
