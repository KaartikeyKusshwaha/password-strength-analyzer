import {defineConfig} from '@playwright/test';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
process.env.SENTINELOPS_E2E_DATA ||= join(tmpdir(),'sentinelops-browser-'+randomUUID());
export default defineConfig({
  testDir:'./acceptance',testMatch:'*.spec.js',workers:1,retries:0,timeout:120000,
  outputDir:'../data/browser-acceptance-results',reporter:'list',
  use:{baseURL:'http://127.0.0.1:18222',headless:true,trace:'off',screenshot:'off',actionTimeout:10000},
  webServer:[
    {command:'python acceptance/serve_app.py',url:'http://127.0.0.1:18221/api/status',reuseExistingServer:false,timeout:30000},
    {command:'npm exec vite -- --config vite.acceptance.config.js',url:'http://127.0.0.1:18222',reuseExistingServer:false,timeout:30000},
  ],
});
