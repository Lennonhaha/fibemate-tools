// Negative control 6: the module name is split, the receiver is aliased.
const c = require('cry' + 'pto');

module.exports = (b) => c.createHash('sha512').update(b).digest('hex');
