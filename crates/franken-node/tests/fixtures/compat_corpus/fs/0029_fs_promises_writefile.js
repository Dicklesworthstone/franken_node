const fs = require('fs');
fs.promises.writeFile('pw.txt', 'promise write').then(() => {
  console.log(fs.readFileSync('pw.txt', 'utf8'));
});
