// Negative control 2: the digest name is assembled from an array.
const crypto = require('crypto');
const NAME = ['sh', 'a256'].join('');

module.exports = (buf) => crypto.createHash(NAME).update(buf).digest('hex');
