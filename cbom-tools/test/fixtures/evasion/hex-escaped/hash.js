// Negative control 5: the name is written as escaped bytes.
const crypto = require('crypto');
const name = '\x73\x68\x61\x32\x35\x36';

module.exports = (b) => crypto.createHash(name).update(b).digest('hex');
