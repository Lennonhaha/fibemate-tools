// Proper test file sibling for sample.testcov.withtest.js
const { mul } = require('./sample.testcov.withtest');
if (mul(2, 3) !== 6) throw new Error('bad');
