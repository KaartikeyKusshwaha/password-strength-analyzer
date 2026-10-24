import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  outputDir: '../data/extension-e2e-results',
  workers: 1,
  retries: 0,
  timeout: 30000,
  reporter: 'list',
});
