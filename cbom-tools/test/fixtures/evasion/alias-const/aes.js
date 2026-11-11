// Negative control 1: the cipher name is a constant, the call site is not.
const crypto = require('crypto');
const ALGO = 'aes-256-gcm';

function encrypt(key, iv, data) {
  const c = crypto.createCipheriv(ALGO, key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}

module.exports = { encrypt };
