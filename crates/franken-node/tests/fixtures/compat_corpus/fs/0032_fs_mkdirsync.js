const fs = require('fs');
fs.mkdirSync('dup');
try {
  fs.mkdirSync('dup');
  console.log('no-throw');
} catch (e) {
  console.log(e.code);
}
