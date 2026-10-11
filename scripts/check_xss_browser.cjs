// Replay saved HTTP responses in an isolated browser; no live-server claim.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { chromium } = require(process.env.RBPO_PLAYWRIGHT_MODULE || path.resolve(__dirname, '../.browser-tools/node_modules/playwright'));
const root = path.resolve(__dirname, '..');
const reportFolders = require('./report_folders.json');
function reportRelative(participant, filename) {
  const key = String(participant).padStart(2, '0');
  const folder = reportFolders[key];
  if (typeof folder !== 'string' || !folder || folder === '.' || folder === '..' || /[\\/]/.test(folder)) {
    throw new Error(`Invalid or missing report folder for participant ${key}`);
  }
  return path.posix.join('reports', folder, 'evidence', filename);
}
function writeEvidence(participant, filename, result) {
  const target = path.join(root, reportRelative(participant, filename));
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, JSON.stringify(result, null, 2) + '\n');
}

(async () => {
  const browser = await chromium.launch({headless: true,
    ...(process.env.RBPO_BROWSER_PATH ? {executablePath: process.env.RBPO_BROWSER_PATH} : {})});
  const tests = [];
  try {
    for (const [participant, filename, vulnerable] of [
      ['02', 'vulnmart-stored-xss', true], ['04', 'vulnerable.js-xss', true],
      ['05', 'fixed-stored-xss', false], ['05', 'fixed.js-xss', false]]) {
      const source = reportRelative(participant, `${filename}.json`);
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
      writeEvidence(participant, `${result.test}.json`, result);
      await context.close();
      console.log(`${passed ? 'PASS' : 'FAIL'} ${result.test}`);
    }
    writeEvidence('05', 'verification-browser-replay.json',
      {tests, passed: tests.filter(t => t.passed).length, total: tests.length});
    if (tests.some(t => !t.passed)) process.exitCode = 1;
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
