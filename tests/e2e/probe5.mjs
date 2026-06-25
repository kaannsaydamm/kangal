import { chromium } from 'playwright-core';
const CHROME = 'C:/Users/kaluclu/AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe';
const browser = await chromium.launch({ headless: true, executablePath: CHROME });
const ctx = await browser.newContext({ viewport: { width: 1700, height: 1100 } });
await ctx.addInitScript(() => { try { localStorage.setItem('kangal.onboarded.v1','1'); } catch {} });
const page = await ctx.newPage();
await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
await page.waitForTimeout(3000);

const info = await page.evaluate(() => {
  // Find the "No assets yet." div or .react-flow root in the right column
  const aside = document.querySelectorAll('aside')[1];
  if (!aside) return 'no aside[1]';
  // Search the whole document for these signals
  const noAssets = Array.from(document.querySelectorAll('div'))
    .find(d => d.innerText === 'No assets yet.');
  const rf = document.querySelector('.react-flow');
  return {
    aside1Children: aside.children.length,
    noAssets: !!noAssets,
    reactFlow: !!rf,
    aside1Text: aside.innerText.slice(0, 300).replace(/\n/g, ' | '),
  };
});
console.log(JSON.stringify(info, null, 2));
await browser.close();
