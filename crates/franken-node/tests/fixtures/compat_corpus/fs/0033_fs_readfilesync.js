const fs = require('fs');
fs.writeFileSync('afile.txt', 'x');
try {
  fs.readFileSync('afile.txt/child.txt', 'utf8');
  console.log('no-throw');
} catch (e) {
  console.log(e.code);
}
