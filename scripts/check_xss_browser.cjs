// Replay saved HTTP responses in an isolated browser; no live-server claim.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { chromium } = require(process.env.RBPO_PLAYWRIGHT_MODULE || path.resolve(__dirname, '../.browser-tools/node_modules/playwright'));
const root = path.resolve(__dirname, '..');

(async () => {
  const browser = await chromium.launch({headless: true,
    ...(process.env.RBPO_BROWSER_PATH ? {executablePath: process.env.RBPO_BROWSER_PATH} : {})});
  const tests = [];
  try {
    for (const [participant, filename, vulnerable] of [
      ['02', 'vulnmart-stored-xss', true], ['04', 'vulnerable.js-xss', true],
      ['05', 'fixed-stored-xss', false], ['05', 'fixed.js-xss', false]]) {
      const source = `reports/participant-${participant}/evidence/${filename}.json`;
      const bytes = fs.readFileSync(path.join(root, source));
      const response = JSON.parse(bytes).details.response;
      const context = await browser.newContext();
      await context.route('**/*', route => route.abort());
      const page = await context.newPage();
      const dialogs = [];
      page.on('dialog', async dialog => { dialogs.push(dialog.message()); await dialog.dismiss(); });
      await page.setContent(response.body, {waitUntil: 'load'});
      const marker = await page.evaluate(() => window.RBPO_XSS === 1);
      const scriptCount = await page.locator('script').count();
      const passed = vulnerable ? marker || dialogs.length > 0 : !marker && dialogs.length === 0 && scriptCount === 0;
      const result = {test: filename + '-browser-replay', passed,
        timestamp_utc: new Date().toISOString(), browser: browser.version(),
        platform: process.platform, method: 'browser_replay_saved_http',
        source, source_sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
        details: {marker, dialogs, scriptCount,
          scope: 'Execution of saved HTTP HTML in a fresh browser context with external requests blocked; live server and session behaviour not retested.'}};
      tests.push(result);
      fs.writeFileSync(path.join(root, `reports/participant-${participant}/evidence/${result.test}.json`), JSON.stringify(result, null, 2) + '\n');
      await context.close();
      console.log(`${passed ? 'PASS' : 'FAIL'} ${result.test}`);
    }
    fs.writeFileSync(path.join(root, 'reports/participant-05/evidence/verification-browser-replay.json'),
      JSON.stringify({tests, passed: tests.filter(t => t.passed).length, total: tests.length}, null, 2) + '\n');
    if (tests.some(t => !t.passed)) process.exitCode = 1;
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
