const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const apiRouter = require('./routes/api');
const viewsRouter = require('./routes/views');
const database = require('./utils/db');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 2
    }
}));

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Content-Security-Policy',
        `default-src 'self'; ` +
        `script-src 'self' 'nonce-${res.locals.cspNonce}' https://cdnjs.cloudflare.com; ` +
        `style-src 'self' 'nonce-${res.locals.cspNonce}' https://cdnjs.cloudflare.com; ` +
        `connect-src *; ` +
        `img-src 'self' data:; ` +
        `frame-ancestors 'none';`
    );
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

app.use('/', viewsRouter);
app.use('/', apiRouter);

app.use((req, res) => {
    res.status(404).json({ error: 'Nothing here... or is there? 👀' });
});

database.initDb(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[+] BugTracker running on port ${PORT}`);
    });
});
