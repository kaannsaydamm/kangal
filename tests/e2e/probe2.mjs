import { chromium } from 'playwright-core';
const CHROME = 'C:/Users/kaluclu/AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe';
const browser = await chromium.launch({ headless: true, executablePath: CHROME });
const page = await browser.newContext({ viewport: { width: 1700, height: 1100 } }).then(c => c.newPage());
await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
await page.waitForTimeout(3000);

// Check the right column: ASSET GRAPH view default; see what shows
const rightCol = await page.evaluate(() => {
  const all = document.querySelectorAll('aside .text-gray-600.font-mono');
  return Array.from(document.querySelectorAll('div')).filter(d => d.innerText === 'No assets yet.').length;
});
console.log('No assets yet divs:', rightCol);

// Try the no-engagement scope-check
const inp = page.locator('input[placeholder="domain or IP"]').first();
console.log('eng input count:', await inp.count());
if (await inp.count() > 0) {
  await inp.fill('api.x.com');
  await inp.press('Enter');
  await page.waitForTimeout(2500);
  const text = await page.evaluate(() => {
    // The scope result is a small div under the engagement panel
    const ph = document.querySelector('input[placeholder="domain or IP"]');
    return ph?.parentElement?.parentElement?.innerText || 'no result';
  });
  console.log('eng result:', text);
}
await browser.close();
