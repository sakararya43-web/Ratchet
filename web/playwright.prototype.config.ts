import { defineConfig } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { resolve } from 'node:path';

const local = resolve('..', '.local/prototype');
const certificate = new X509Certificate(readFileSync(resolve(local, 'server.pem')));
const spki = createHash('sha256').update(certificate.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');

export default defineConfig({
  testDir: './e2e', fullyParallel: false, workers: 1, retries: 0, timeout: 180_000,
  expect: { timeout: 30_000 }, outputDir: resolve(local, 'browser-artifacts'),
  reporter: [['line'], ['json', { outputFile: resolve(local, 'browser-results.json') }]],
  use: {
    baseURL: 'https://localhost:8444', trace: 'off', screenshot: 'only-on-failure',
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${spki}`] },
  },
});
