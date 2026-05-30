const helpers = require('../utils/helpers');
const CSRF_ACTION = 'tracker_op';

const csrfTokens = new Map();

// Tokens expire after 15 minutes
const TOKEN_TTL_MS = 15 * 60 * 1000;



function generateToken() {
    const token = helpers.generateSecureRandom(32);
    csrfTokens.set(token, { action: CSRF_ACTION, createdAt: Date.now() });
    return token;
}

function csrfMiddleware(req, res, next) {
    const origin = req.headers['origin'];
    if (!origin || typeof origin !== 'string') {
        return res.status(403).json({ error: 'Missing Origin header' });
    }


    const token = req.headers['x-csrf-token'];
    const action = req.headers['x-csrf-action'];

    if (!token || !action) {
        return res.status(403).json({ error: 'Missing CSRF token or action' });
    }

    const stored = csrfTokens.get(token);
    if (!stored || stored.action !== action) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    // Check expiration
    if (Date.now() - stored.createdAt > TOKEN_TTL_MS) {
        csrfTokens.delete(token);
        return res.status(403).json({ error: 'CSRF token expired, refresh the page' });
    }

    // Invalidate after single use
    csrfTokens.delete(token);
    next();
}

setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [token, data] of csrfTokens) {
        if (now - data.createdAt > TOKEN_TTL_MS) {
            csrfTokens.delete(token);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[csrf] Cleaned ${cleaned} expired token(s). Active: ${csrfTokens.size}`);
    }
}, 5 * 60 * 1000);

module.exports = { generateToken, csrfMiddleware, CSRF_ACTION };
