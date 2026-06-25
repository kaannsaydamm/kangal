import { chromium } from 'playwright-core';
const browser = await chromium.launch({ headless: true, executablePath: 'C:/Users/kaluclu/AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe' });
const ctx = await browser.newContext({ viewport: { width: 1700, height: 1100 } });
await ctx.addInitScript(() => { try { localStorage.setItem('kangal.onboarded.v2', '1'); } catch {} });
const page = await ctx.newPage();
await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
await page.waitForTimeout(3000);
await page.evaluate(() => {
  const b = Array.from(document.querySelectorAll('button')).find(x => /TOOL MGR/i.test(x.innerText));
  if (b) b.click();
});
await page.waitForTimeout(2500);
const beforeText = await page.evaluate(() => document.body.innerText);
console.log('BEFORE has 106/106:', /(\d+)\/(\d+) tools/.exec(beforeText)?.[0]);

// Use Playwright's selectOption API
const select = await page.$('select');
const options = await page.evaluate(() => Array.from(document.querySelector('select')?.options || []).map(o => ({ value: o.value, text: o.textContent })));
console.log('OPTIONS sample:', options.slice(0, 5));

if (select) {
  await select.selectOption('web_exploit');
  await page.waitForTimeout(800);
  const afterText = await page.evaluate(() => document.body.innerText);
  console.log('AFTER selectOption web_exploit:', /(\d+)\/(\d+) tools/.exec(afterText)?.[0]);
}

await browser.close();
