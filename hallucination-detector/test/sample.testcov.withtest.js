// Regression sample: a source file that DOES have a proper .test.js sibling.
// findTestFor() must locate sample.testcov.withtest.test.js as its test.
function mul(a, b) {
  return a * b;
}
module.exports = { mul };
