import { defineConfig } from "../../frontend/node_modules/vite/dist/node/index.js";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({
  root,
  resolve: {
    alias: {
      "react-dom": path.resolve(root, "../../frontend/node_modules/react-dom"),
      react: path.resolve(root, "../../frontend/node_modules/react"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: false,
    rollupOptions: { input: [path.join(root, "popup.html"), path.join(root, "vault-frame.html")] },
  },
});
