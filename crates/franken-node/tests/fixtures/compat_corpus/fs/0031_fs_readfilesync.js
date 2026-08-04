const fs = require('fs');
try {
  fs.readFileSync('does-not-exist.txt', 'utf8');
  console.log('no-throw');
} catch (e) {
  console.log(e.code);
}
