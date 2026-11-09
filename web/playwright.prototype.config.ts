import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

const profile=process.env.RATCHET_LOCAL_PROFILE??'prototype';
if(!['prototype','completion-a'].includes(profile))throw new Error('Unknown local acceptance profile');
const local = resolve('..', '.local', profile);

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
  },
});
