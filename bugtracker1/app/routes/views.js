const express = require('express');
const router = express.Router();
const csrf = require('../middleware/csrf');

function authMiddleware(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

router.get('/', authMiddleware, (req, res) => {
    res.redirect('/dashboard');
});

//lightweight health endpoint for monitoring
router.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: Math.floor(process.uptime()), timestamp: new Date().toISOString() });
});

router.get('/login', (req, res) => {
    if (req.session && req.session.userId) return res.redirect('/dashboard');
    res.render('login', { nonce: res.locals.cspNonce, error: null });
});

//jking
router.get('/search', authMiddleware, (req, res) => {
    return res.json({
        message: 'SQL injection found! Shutting down in 3... 2... 1... just kidding. Nice try anyway',
    });
});

router.get('/register', (req, res) => {
    if (req.session && req.session.userId) return res.redirect('/dashboard');
    res.render('register', { nonce: res.locals.cspNonce, error: null });
});

router.get('/dashboard', authMiddleware, (req, res) => {
    res.render('dashboard', {
        nonce: res.locals.cspNonce,
        username: req.session.username,
        role: req.session.role
    });
});

router.get('/profile', authMiddleware, (req, res) => {
    const csrfToken = csrf.generateToken();
    res.render('profile', {
        nonce: res.locals.cspNonce,
        username: req.session.username,
        role: req.session.role,
        csrfToken,
        csrfAction: csrf.CSRF_ACTION
    });
});

// Submit a bug report
router.get('/submit', authMiddleware, (req, res) => {
    const csrfToken = csrf.generateToken();
    res.render('submit', {
        nonce: res.locals.cspNonce,
        csrfToken,
        csrfAction: csrf.CSRF_ACTION
    });
});

router.get('/review', authMiddleware, (req, res) => {
    if (req.session.role === 'reporter') {
        const returnUrl = req.query.returnUrl || '/dashboard';
        return res.redirect(returnUrl);
    }
    const csrfToken = csrf.generateToken();
    res.render('review', {
        nonce: res.locals.cspNonce,
        csrfToken,
        csrfAction: csrf.CSRF_ACTION
    });
});

router.get('/about', authMiddleware, (req, res) => {
    res.render('about', {
        nonce: res.locals.cspNonce
    });
});

router.get('/report', authMiddleware, (req, res) => {
    req.session.powSalt = require('crypto').randomBytes(8).toString('hex');
    res.render('report', {
        nonce: res.locals.cspNonce,
        username: req.session.username,
        powSalt: req.session.powSalt
    });
});

module.exports = router;
