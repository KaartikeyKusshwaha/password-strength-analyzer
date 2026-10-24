import {defineConfig} from '../../frontend/node_modules/vite/dist/node/index.js';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({root,publicDir:false,build:{outDir:'dist',emptyOutDir:false,lib:{entry:path.join(root,'worker-entry.js'),name:'SentinelOpsWorker',formats:['iife'],fileName:()=> 'background.js'},rollupOptions:{output:{inlineDynamicImports:true}}}});
