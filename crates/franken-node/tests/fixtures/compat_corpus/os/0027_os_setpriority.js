const os = require('os');
try {
  os.setPriority(0, 1000);
  console.log('no-throw');
} catch (err) {
  console.log('threw:' + (err instanceof RangeError));
}
