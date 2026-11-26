const os = require('os');
for (const [label, fn] of [
  ['low', () => os.setPriority(0, -21)],
  ['high', () => os.setPriority(0, 20)],
  ['floatPid', () => os.setPriority(1.5, 0)],
]) {
  try {
    fn();
    console.log(label + ':no-throw');
  } catch (err) {
    console.log(label + ':' + (err instanceof RangeError) + ':' + err.code);
  }
}
