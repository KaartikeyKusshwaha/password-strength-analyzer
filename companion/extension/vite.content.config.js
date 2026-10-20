import { defineConfig } from "../../frontend/node_modules/vite/dist/node/index.js";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({
  root,
  publicDir: false,
  resolve: {
    alias: {
      "@zxcvbn-ts/core": path.resolve(
        root,
        "../../frontend/node_modules/@zxcvbn-ts/core",
      ),
      "@zxcvbn-ts/language-common": path.resolve(
        root,
        "../../frontend/node_modules/@zxcvbn-ts/language-common",
      ),
      "@zxcvbn-ts/language-en": path.resolve(
        root,
        "../../frontend/node_modules/@zxcvbn-ts/language-en",
      ),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    lib: {
      entry: path.join(root, "content.js"),
      name: "SentinelOpsContent",
      formats: ["iife"],
      fileName: () => "content.js",
    },
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
});
