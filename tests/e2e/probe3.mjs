import { chromium } from 'playwright-core';
const CHROME = 'C:/Users/kaluclu/AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe';
const browser = await chromium.launch({ headless: true, executablePath: CHROME });
const page = await browser.newContext({ viewport: { width: 1700, height: 1100 } }).then(c => c.newPage());
await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
await page.waitForTimeout(3000);

const inp = page.locator('input[placeholder="domain or IP"]').first();
await inp.fill('api.x.com');
// Click CHECK
await page.locator('button:has-text("CHECK")').first().click();
await page.waitForTimeout(2500);

const result = await page.evaluate(() => {
  const ph = document.querySelector('input[placeholder="domain or IP"]');
  if (!ph) return 'no input';
  // Result is sibling below the input row
  const row = ph.parentElement;
  return row?.innerText || 'no row';
});
console.log('after click CHECK, row text:', JSON.stringify(result));

// Also dump a wider area
const wider = await page.evaluate(() => {
  const ph = document.querySelector('input[placeholder="domain or IP"]');
  return ph?.closest('div')?.parentElement?.innerText || 'no container';
});
console.log('wider:', JSON.stringify(wider));
await browser.close();
