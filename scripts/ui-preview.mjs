// Open the local redesign using normal browser certificate verification.
import { chromium } from '../web/node_modules/@playwright/test/index.mjs';
const browser = await chromium.launch({ headless: false });
try {
  const page = await browser.newPage({ viewport: null });
  await page.goto('https://localhost:8444');
  console.log('Ratchet open with verified HTTPS at https://localhost:8444');
  await new Promise(resolve => browser.on('disconnected', resolve));
} catch (error) {
  await browser.close();
  console.error('Local HTTPS could not be verified. On Windows run: powershell -File scripts/trust-local-https.ps1');
  throw error;
}
