const path = require('path');
const calls = [
  () => path.basename(123),
  () => path.dirname(null),
  () => path.extname({}),
  () => path.normalize(42),
  () => path.isAbsolute(false),
];
for (const fn of calls) {
  try {
    fn();
    console.log('no-throw');
  } catch (e) {
    console.log(e instanceof TypeError, e.code);
  }
}
