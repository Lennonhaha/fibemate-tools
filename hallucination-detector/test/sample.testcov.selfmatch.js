// Regression sample: a source file living under test/ with NO .test.js sibling.
// Before the fix, findTestFor() self-matched this file (candidate 4 == srcPath)
// and wrongly reported it as "covered". After the fix it must be reported uncovered.
function add(a, b) {
  return a + b;
}
module.exports = { add };
