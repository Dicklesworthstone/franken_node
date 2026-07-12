const os = require('os');
try {
  os.setPriority('not-a-pid', 0);
  console.log('no-throw');
} catch (err) {
  console.log('threw:' + (err instanceof TypeError));
  console.log('code:' + err.code);
}
