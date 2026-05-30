const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

let db;

const FLAG = process.env.FLAG || 'THEM?!CTF{pavel_is_gay}';
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');

const SALT_ROUNDS = 10;

function hashPassword(password) {
    return bcrypt.hashSync(password, SALT_ROUNDS);
}

function verifyPassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

function initDb(callback) {
    db = new sqlite3.Database(':memory:', (err) => {
        if (err) {
            console.error('[-] DB connection failed:', err.message);
            throw err;
        }
        console.log('[+] Connected to in-memory SQLite database.');
    });

    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin','editor','reporter')) DEFAULT 'reporter',
            recovery_key TEXT DEFAULT NULL
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            severity TEXT DEFAULT 'LOW',
            status TEXT DEFAULT 'pending',
            visibility TEXT DEFAULT 'public',
            author TEXT NOT NULL,
            FOREIGN KEY(author) REFERENCES users(username)
        )`);

        const adminHash = hashPassword(ADMIN_PASSWORD);
        db.run(
            `INSERT OR REPLACE INTO users (id, username, password, role, recovery_key)
             VALUES (1, ?, ?, 'admin', NULL)`,
            [ADMIN_USERNAME, adminHash]
        );

        db.run(
            `INSERT OR REPLACE INTO reports (id, title, body, severity, status, visibility, author)
             VALUES (1, 'Internal Security Assessment', ?, 'CRITICAL', 'approved', 'private', ?)`, 
            [FLAG, ADMIN_USERNAME]
        );

        db.run(
            `INSERT OR REPLACE INTO reports (id, title, body, severity, status, visibility, author)
             VALUES (2, 'SQL Injection in search endpoint', 'Found a critical SQL injection vulnerability in the /search endpoint. HIGH impact.', 'HIGH', 'approved', 'public', ?)`,
            [ADMIN_USERNAME]
        );
    });

    if (callback) setTimeout(callback, 200);
}

function createUser(username, password) {
    return new Promise((resolve, reject) => {
        const hash = hashPassword(password);
        db.run(
            `INSERT INTO users (username, password, role) VALUES (?, ?, 'reporter')`,
            [username, hash],
            function (err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, username, role: 'reporter' });
            }
        );
    });
}

function getUserByUsername(username) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function getUserById(id) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function updateRecoveryKey(userId, recoveryKey) {
    return new Promise((resolve, reject) => {
        db.run(
            `UPDATE users SET recovery_key = ? WHERE id = ?`,
            [recoveryKey, userId],
            (err) => {
                if (err) reject(err);
                else resolve();
            }
        );
    });
}

function resetPasswordByRecoveryKey(username, recoveryKey, newPassword) {
    return new Promise((resolve, reject) => {
        db.get(
            `SELECT * FROM users WHERE username = ? AND recovery_key = ?`,
            [username, recoveryKey],
            (err, row) => {
                if (err) return reject(err);
                if (!row) return resolve(null); // not found
                const newHash = hashPassword(newPassword);
                db.run(
                    `UPDATE users SET password = ?, recovery_key = NULL WHERE id = ?`,
                    [newHash, row.id],
                    (err2) => {
                        if (err2) reject(err2);
                        else resolve(row);
                    }
                );
            }
        );
    });
}

function createReport(title, body, severity, author) {
    return new Promise((resolve, reject) => {
        db.run(
            `INSERT INTO reports (title, body, severity, status, visibility, author)
             VALUES (?, ?, ?, 'pending', 'public', ?)`,
            [title, body, severity, author],
            function (err) {
                if (err) reject(err);
                else resolve({ id: this.lastID });
            }
        );
    });
}

function getPendingReports() {
    return new Promise((resolve, reject) => {
        db.all(
            `SELECT * FROM reports WHERE status = 'pending' AND visibility = 'public'`,
            [],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            }
        );
    });
}

function getReportsByAuthor(author) {
    return new Promise((resolve, reject) => {
        db.all(
            `SELECT * FROM reports WHERE author = ? AND visibility = 'public'`,
            [author],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            }
        );
    });
}

function getReportById(id) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT * FROM reports WHERE id = ?`, [id], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function approveReport(id) {
    return new Promise((resolve, reject) => {
        db.run(
            `UPDATE reports SET status = 'approved' WHERE id = ?`,
            [id],
            (err) => {
                if (err) reject(err);
                else resolve();
            }
        );
    });
}

function updateReport(id, title, body, severity, visibility) {
    return new Promise((resolve, reject) => {
        db.run(
            `UPDATE reports SET title = ?, body = ?, severity = ?, visibility = ? WHERE id = ?`,
            [title, body, severity, visibility, id],
            (err) => {
                if (err) reject(err);
                else resolve();
            }
        );
    });
}

function getAllPublicApprovedReports() {
    return new Promise((resolve, reject) => {
        db.all(
            `SELECT * FROM reports WHERE status = 'approved' AND visibility = 'public'`,
            [],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            }
        );
    });
}

function getAllReportsForAdmin() {
    return new Promise((resolve, reject) => {
        db.all(
            `SELECT * FROM reports WHERE status = 'approved'`,
            [],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            }
        );
    });
}

module.exports = {
    initDb,
    hashPassword,
    verifyPassword,
    createUser,
    getUserByUsername,
    getUserById,
    updateRecoveryKey,
    resetPasswordByRecoveryKey,
    createReport,
    getPendingReports,
    getReportsByAuthor,
    getReportById,
    approveReport,
    updateReport,
    getAllPublicApprovedReports,
    getAllReportsForAdmin
};
