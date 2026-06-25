import { chromium } from 'playwright-core';
const CHROME = 'C:/Users/kaluclu/AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe';
const browser = await chromium.launch({ headless: true, executablePath: CHROME });
const ctx = await browser.newContext({ viewport: { width: 1700, height: 1100 } });
await ctx.addInitScript(() => { try { localStorage.setItem('kangal.onboarded.v1','1'); } catch {} });
const page = await ctx.newPage();
await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
await page.waitForTimeout(3000);

// Engage a scan
const e = await page.evaluate(() => {
  const inp = document.querySelector('input[placeholder*="domain" i], input[placeholder*="target" i]');
  if (inp) inp.value = 'example.com';
  const btn = Array.from(document.querySelectorAll('button')).find(b => /^engage$/i.test(b.innerText.trim()));
  if (btn) { btn.click(); return true; }
  return false;
});
console.log('engaged:', e);
await page.waitForTimeout(8000);

// Look for asset graph elements
const info = await page.evaluate(() => {
  // Find the graph view button in the right column
  const btns = Array.from(document.querySelectorAll('button'))
    .filter(b => /asset graph|intel|toolbox/i.test(b.innerText));
  return btns.map(b => ({ text: b.innerText.trim(), visible: b.offsetParent !== null }));
});
console.log('right-column tabs:', info);

// Try to find what's actually in the right column
const r = await page.evaluate(() => {
  const asides = document.querySelectorAll('aside');
  return Array.from(asides).map((a, i) => ({
    idx: i,
    text: a.innerText.slice(0, 200).replace(/\n/g, ' | '),
    kids: a.children.length,
  }));
});
console.log('asides:', r);

// What's selected in scan history?
const sc = await page.evaluate(() => {
  // Find the first scan id in the history
  const list = document.querySelector('aside');
  return list?.innerText.slice(0, 300) || 'none';
});
console.log('aside 0 text:', sc);

await browser.close();
