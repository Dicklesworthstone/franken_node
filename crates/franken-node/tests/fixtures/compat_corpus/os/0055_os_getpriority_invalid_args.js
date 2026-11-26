const os = require('os');
try {
  os.getPriority('abc');
  console.log('str:no-throw');
} catch (err) {
  console.log('str:' + (err instanceof TypeError) + ':' + err.code);
}
try {
  os.getPriority(1.5);
  console.log('float:no-throw');
} catch (err) {
  console.log('float:' + (err instanceof RangeError) + ':' + err.code);
}
