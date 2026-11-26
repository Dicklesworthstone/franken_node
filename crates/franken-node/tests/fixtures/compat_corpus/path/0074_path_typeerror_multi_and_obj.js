const path = require('path');
const calls = [
  () => path.relative('/a', 1),
  () => path.resolve('/a', null),
  () => path.parse(123),
  () => path.format('str'),
];
for (const fn of calls) {
  try {
    fn();
    console.log('no-throw');
  } catch (e) {
    console.log(e instanceof TypeError, e.code);
  }
}
