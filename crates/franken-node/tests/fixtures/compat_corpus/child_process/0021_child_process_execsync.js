const cp = require('child_process');
try {
  cp.execSync('printf "aaaaaaaaaaaaaaaaaaaa"', { maxBuffer: 4 });
  console.log('no-throw:true');
} catch (e) {
  console.log('threw:' + (e instanceof Error));
  console.log('code:' + e.code);
}
