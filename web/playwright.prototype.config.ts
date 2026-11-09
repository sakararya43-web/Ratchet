import { defineConfig } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { resolve } from 'node:path';

const profile=process.env.RATCHET_LOCAL_PROFILE??'prototype';
if(!['prototype','completion-a'].includes(profile))throw new Error('Unknown local acceptance profile');
const local = resolve('..', '.local', profile);

// Pin the exact public key of this profile's server certificate. Chromium accepts only
// that key for localhost; any other certificate is still rejected. This lets acceptance
// run where the local CA is not in the OS trust store (CI) without disabling verification.
const serverCertificate = resolve(local, 'server.pem');
const pin = existsSync(serverCertificate)
  ? createHash('sha256').update(new X509Certificate(readFileSync(serverCertificate)).publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
  : '';

export default defineConfig({
  testDir: './e2e',
  // Each local profile owns its journeys; the Authority spec needs the live-genesis profile.
  testMatch: profile === 'completion-a' ? /authority\.spec\.ts$/ : /(prototype|landing)\.spec\.ts$/,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 30_000 }, outputDir: resolve(local, 'browser-artifacts'),
  reporter: [['line'], ['json', { outputFile: resolve(local, 'browser-results.json') }]],
  use: {
    baseURL: 'https://localhost:8444', actionTimeout: 10_000, navigationTimeout: 10_000,
    trace: 'off', screenshot: 'only-on-failure',
    launchOptions: { args: pin ? [`--ignore-certificate-errors-spki-list=${pin}`] : [] },
  },
});
