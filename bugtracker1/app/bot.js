const { chromium } = require('playwright');
const crypto = require('crypto');

const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');

const BROWSER_ARGS = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--no-gpu',
    '--disable-default-apps',
    '--disable-translate',
    '--disable-extensions',
    '--disable-software-rasterizer',
    '--disable-xss-auditor'
];

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function visitAsAdmin(urlToVisit) {
    let parsed;
    try {
        parsed = new URL(urlToVisit);
    } catch (_) {
        console.error('[bot] Invalid URL:', urlToVisit);
        return false;
    }

    const allowed = ['localhost', '127.0.0.1'];
    if (!allowed.includes(parsed.hostname)) {
        console.error('[bot] Hostname not allowed:', parsed.hostname);
        return false;
    }

    let browser;
    try {
        browser = await chromium.launch({ headless: true, args: BROWSER_ARGS });
    } catch (err) {
        console.error('[bot] Failed to launch browser:', err.message);
        return false;
    }

    const context = await browser.newContext();

    try {
        const page = await context.newPage();

        // Login as admin
        console.log('[bot] Logging in as admin...');
        await page.goto(`${APP_URL}/login`, { waitUntil: 'load', timeout: 10_000 });
        await page.fill('input[name="username"]', ADMIN_USERNAME);
        await page.fill('input[name="password"]', ADMIN_PASSWORD);
        await page.click('button.btn-primary');
        await sleep(2000);

        // Verify login worked
        const currentUrl = page.url();
        if (currentUrl.includes('/login')) {
            console.error('[bot] Login failed — still on login page. Check ADMIN_PASSWORD env var.');
            return false;
        }
        console.log('[bot] Login successful, navigating to target...');

        console.log(`[bot] Visiting: ${urlToVisit}`);
        await page.goto(urlToVisit, { waitUntil: 'load', timeout: 10_000 });
        await sleep(5000);

        try {
            await page.click('input[type="submit"][value="Approve"]', { timeout: 5000 });
            console.log('[bot] Clicked Approve button.');
            await sleep(3000);
        } catch (_) {
            console.log('[bot] No Approve button found (or already clicked)');
        }

        console.log('[bot] Done.');
        return true;
    } catch (err) {
        console.error('[bot] Error:', err.message);
        return false;
    } finally {
        await context.close();
        await browser.close();
    }
}

module.exports = { visitAsAdmin };
