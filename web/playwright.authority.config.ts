import { defineConfig } from '@playwright/test';
import { readFileSync, existsSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { resolve } from 'node:path';

const local = resolve('..', '.local/completion-a');
const protoLocal = resolve('..', '.local/prototype');
let spki = '';
const certPath = existsSync(resolve(local, 'server.pem'))
  ? resolve(local, 'server.pem')
  : resolve(protoLocal, 'server.pem');
if (existsSync(certPath)) {
  const certificate = new X509Certificate(readFileSync(certPath));
  spki = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
}

export default defineConfig({
  testDir: './e2e',
  testMatch: /authority\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 30_000 },
  outputDir: resolve(local, 'browser-artifacts'),
  reporter: [['line'], ['json', { outputFile: resolve(local, 'authority-results.json') }]],
  use: {
    baseURL: 'https://localhost:8444',
    actionTimeout: 10_000,
    navigationTimeout: 10_000,
    trace: 'off',
    screenshot: 'only-on-failure',
    launchOptions: { args: spki ? [`--ignore-certificate-errors-spki-list=${spki}`] : [] },
  },
});
