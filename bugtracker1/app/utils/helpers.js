const crypto = require('crypto');

function generateSecureRandom(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

function validateUsername(username) {
    if (!username || typeof username !== 'string') return false;
    return /^[a-zA-Z0-9_]{3,64}$/.test(username);
}

function validatePassword(password) {
    //password=password.trim(); i was almost causing a crash because of this
    if (!password || typeof password !== 'string') return false;
    if (password.includes('|')) return false;
    return password.length >= 8 && password.length <= 128;
}

function validateSeverity(severity) {
    return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity);
}

function validateVisibility(visibility) {
    return ['public', 'private'].includes(visibility);
}

module.exports = {
    generateSecureRandom,
    validateUsername,
    validatePassword,
    validateSeverity,
    validateVisibility
};
