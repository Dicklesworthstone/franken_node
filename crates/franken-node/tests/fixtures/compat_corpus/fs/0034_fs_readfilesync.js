const fs = require('fs');
fs.mkdirSync('justdir');
try {
  fs.readFileSync('justdir');
  console.log('no-throw');
} catch (e) {
  console.log(e.code);
}
