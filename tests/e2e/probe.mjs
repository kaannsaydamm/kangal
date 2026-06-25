import { chromium } from 'playwright-core';
const CHROME = 'C:/Users/kaluclu/AppData/Local/ms-playwright/chromium-1223/chrome-win64/chrome.exe';
const browser = await chromium.launch({ headless: true, executablePath: CHROME });
const page = await browser.newContext({ viewport: { width: 1700, height: 1100 } }).then(c => c.newPage());
page.on('pageerror', e => console.log('PAGE ERR', String(e)));
page.on('console', m => { if (m.type() === 'error') console.log('CONSOLE', m.text()); });
await page.goto('http://localhost:5173', { waitUntil: 'networkidle' });
await page.waitForTimeout(3000);

// Probe 1: open MEMORY modal, fill input, see what happens
await page.evaluate(() => {
  const m = Array.from(document.querySelectorAll('button')).find(b => b.innerText.trim().startsWith('MEMORY'));
  if (m) m.click();
});
await page.waitForTimeout(1500);
const dialog = await page.evaluate(() => {
  const d = document.querySelector('[role="dialog"]');
  if (!d) return { exists: false, html: '<no dialog>', inputs: 0 };
  return {
    exists: true,
    inputs: d.querySelectorAll('input').length,
    placeholders: Array.from(d.querySelectorAll('input')).map(i => i.placeholder),
    title: d.querySelector('h1,h2,h3')?.innerText,
    bodyText: d.innerText.slice(0, 200),
  };
});
console.log('MEMORY modal:', JSON.stringify(dialog, null, 2));

// Try filling and submitting
const inps = await page.locator('[role="dialog"] input').count();
console.log('inputs in dialog:', inps);
if (inps > 0) {
  const ph = await page.locator('[role="dialog"] input').first().getAttribute('placeholder');
  console.log('first placeholder:', ph);
  await page.locator('[role="dialog"] input').first().fill('apache');
  await page.locator('[role="dialog"] input').first().press('Enter');
  await page.waitForTimeout(3000);
  const dialog2 = await page.evaluate(() => {
    const d = document.querySelector('[role="dialog"]');
    return d ? d.innerText.slice(0, 500) : '<no dialog>';
  });
  console.log('after search dialog text:', dialog2);
}

await page.screenshot({ path: 'C:/Users/kaluclu/Desktop/kangal/.tmp-probe-memory.png' });

// Probe 2: close dialog, find engagement panel scope-check
await page.keyboard.press('Escape');
await page.waitForTimeout(500);

const engInputs = await page.evaluate(() => {
  return Array.from(document.querySelectorAll('input'))
    .map(i => ({ placeholder: i.placeholder, value: i.value, type: i.type }));
});
console.log('all inputs:', JSON.stringify(engInputs, null, 2));

// Probe 3: React Flow root class
const rf = await page.evaluate(() => {
  const candidates = ['.react-flow', '.react-flow__renderer', '.react-flow__viewport'];
  return candidates.map(c => ({ sel: c, count: document.querySelectorAll(c).length }));
});
console.log('RF selectors:', JSON.stringify(rf));

await page.screenshot({ path: 'C:/Users/kaluclu/Desktop/kangal/.tmp-probe.png' });
await browser.close();
