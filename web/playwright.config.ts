import { defineConfig, devices } from '@playwright/test';
import { existsSync } from 'node:fs';

const chromiumExecutable = process.env.CF_PLAYWRIGHT_CHROMIUM ??
  ['/usr/bin/chromium', '/usr/bin/chromium-browser'].find(existsSync);

export default defineConfig({
  testDir: './e2e',
  outputDir: './test-results',
  fullyParallel: false,
  reporter: [
    ['list'],
    ['html', { outputFolder: './playwright-report', open: 'never' }],
  ],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run build && npm run preview -- --host 0.0.0.0 --port 4173 --strictPort',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    stdout: 'pipe',
    stderr: 'pipe',
    timeout: 120_000,
  },
  projects: [{
    name: 'chromium',
    use: {
      ...devices['Desktop Chrome'],
      launchOptions: chromiumExecutable === undefined
        ? undefined
        : { executablePath: chromiumExecutable },
    },
  }],
});
