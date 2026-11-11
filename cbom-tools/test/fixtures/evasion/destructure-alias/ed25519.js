// Negative control 7: destructured import, curve name as plain data.
const { sign } = require('node:crypto');
const CURVE = 'ed25519';

function signMessage(msg, key) {
  return sign(null, Buffer.from(msg), { key, dsaEncoding: 'ieee-p1363' });
}

module.exports = { signMessage, CURVE };
