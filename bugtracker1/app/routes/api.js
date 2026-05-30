const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const db = require('../utils/db');
const helpers = require('../utils/helpers');
const csrf = require('../middleware/csrf');
const bot = require('../bot');

function authMiddleware(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

//trying not to destroy the infra
const loginLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: 'Too many login attempts' }
});

const reportLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many report submissions' }
});

router.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!helpers.validateUsername(username)) {
            return res.json({ error: 'Invalid username (3-64 alphanumeric/underscore)' });
        }
        if (!helpers.validatePassword(password)) {
            return res.json({ error: 'Invalid password (8-128 chars, no pipe character)' });
        }
        const user = await db.createUser(username, password);
        return res.json({ status: 'ok', message: 'Account created. Please log in.' });
    } catch (err) {
        if (err.message && err.message.includes('UNIQUE')) {
            return res.json({ error: 'Username already taken' });
        }
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!helpers.validateUsername(username) || !helpers.validatePassword(password)) {
            return res.json({ error: 'Invalid credentials' });
        }
        const user = await db.getUserByUsername(username);
        if (!user || !db.verifyPassword(password, user.password)) {
            return res.json({ error: 'Invalid credentials' });
        }
        req.session.regenerate((err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            return res.json({ status: 'ok' });
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/logout', (req, res) => {
    req.session.destroy();
    return res.redirect('/login');
});

router.get('/redirect', (req, res) => {
    const target = req.query.url;
    if (!target) {
        return res.status(400).send('Missing url parameter');
    }
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
        return res.status(400).send('Only http/https URLs are allowed');
    }
    return res.redirect(302, target);
});

router.get('/api/reports/pending', authMiddleware, async (req, res) => {
    if (req.session.role === 'reporter') {
        return res.status(403).json({ error: 'Insufficient privileges' });
    }
    try {
        const reports = await db.getPendingReports();
        return res.json(reports);
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/reports/:author', authMiddleware, async (req, res) => {
    try {
        const reports = await db.getReportsByAuthor(req.params.author);
        return res.json(reports);
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/api/report', authMiddleware, async (req, res) => {
    try {
        const { title, body, severity } = req.body;
        if (!title || !body || typeof title !== 'string' || typeof body !== 'string') {
            return res.json({ error: 'Invalid input' });
        }
        if (title.length > 200 || body.length > 2000) {
            return res.json({ error: 'Input too long' });
        }
        const sev = helpers.validateSeverity(severity) ? severity : 'LOW';
        const report = await db.createReport(title, body, sev, req.session.username);
        return res.json({ status: 'ok', id: report.id });
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/api/report/:id/approve', authMiddleware, csrf.csrfMiddleware, async (req, res) => {
    try {
        if (req.session.role === 'reporter') {
            return res.status(403).json({ error: 'Insufficient privileges' });
        }
        const report = await db.getReportById(req.params.id);
        if (!report) {
            return res.json({ error: 'Report not found' });
        }
        if (report.status !== 'pending') {
            return res.json({ error: 'Report is not pending' });
        }
        await db.approveReport(req.params.id);
        return res.json({ status: 'ok', message: 'Report approved' });
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.patch('/api/report/:id', authMiddleware, csrf.csrfMiddleware, async (req, res) => {
    try {
        if (req.session.role === 'reporter') {
            return res.status(403).json({ error: 'Insufficient privileges' });
        }
        const report = await db.getReportById(req.params.id);
        if (!report) {
            return res.json({ error: 'Report not found' });
        }
        const title      = req.body.title      || report.title;
        const body       = req.body.body       || report.body;
        const severity   = req.body.severity   || report.severity;
        const visibility = req.body.visibility || report.visibility;

        if (typeof title !== 'string' || typeof body !== 'string') {
            return res.json({ error: 'Invalid input' });
        }
        if (title.length > 200 || body.length > 2000) {
            return res.json({ error: 'Input too long' });
        }
        if (!helpers.validateSeverity(severity) || !helpers.validateVisibility(visibility)) {
            return res.json({ error: 'Invalid severity or visibility' });
        }
        await db.updateReport(req.params.id, title, body, severity, visibility);
        return res.json({ status: 'ok', message: 'Report updated' });
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

//i care for my dear users
router.post('/api/account/recovery-key', authMiddleware, csrf.csrfMiddleware, async (req, res) => {
    try {
        const { recovery_key } = req.body;
        if (!recovery_key || typeof recovery_key !== 'string' || recovery_key.length > 128) {
            return res.json({ error: 'Invalid recovery key' });
        }
        await db.updateRecoveryKey(req.session.userId, recovery_key);
        return res.json({ status: 'ok', message: 'Recovery key updated' });
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});


router.post('/api/reset-password', async (req, res) => {
    try {
        const { username, recovery_key, new_password } = req.body;
        if (!helpers.validateUsername(username)) {
            return res.json({ error: 'Invalid username' });
        }
        if (!recovery_key || typeof recovery_key !== 'string') {
            return res.json({ error: 'Invalid recovery key' });
        }
        if (!helpers.validatePassword(new_password)) {
            return res.json({ error: 'Invalid new password' });
        }
        const user = await db.resetPasswordByRecoveryKey(username, recovery_key, new_password);
        if (!user) {
            return res.json({ error: 'Invalid credentials or recovery key' });
        }
        return res.json({ status: 'ok', message: 'Password reset successfully. Please log in.' });
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/api/submit-url', authMiddleware, reportLimiter, async (req, res) => {
    try {
        const { url, powNonce } = req.body;
        if (!url || typeof url !== 'string') {
            return res.json({ error: 'Invalid URL' });
        }
        if (!powNonce || !req.session.powSalt) {
            return res.json({ error: 'Missing Proof of Work' });
        }

        // Verify PoW
        const hash = require('crypto').createHash('sha256').update(req.session.powSalt + powNonce).digest('hex');
        if (!hash.startsWith('0000')) {
            return res.json({ error: 'Invalid Proof of Work hash' });
        }
        req.session.powSalt = null; // Consume salt

        let parsed;
        try { parsed = new URL(url); } catch (_) {
            console.log(url)
            return res.json({ error: 'Invalid URL format' });
        }
        if (!['localhost', '127.0.0.1'].includes(parsed.hostname)) {
            return res.json({ error: 'URL must point to localhost' });
        }

        const ok = await bot.visitAsAdmin(url);
        if (!ok) {
            return res.status(500).json({ error: 'Admin failed to visit the URL' });
        }
        return res.json({ status: 'ok', message: 'Admin visited the URL successfully' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/api/dashboard', authMiddleware, async (req, res) => {
    try {
        let reports;
        if (req.session.role === 'admin') {
            reports = await db.getAllReportsForAdmin();
        } else {
            reports = await db.getAllPublicApprovedReports();
        }
        return res.json(reports);
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
