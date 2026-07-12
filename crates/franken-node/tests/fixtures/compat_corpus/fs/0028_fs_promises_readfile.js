const fs = require('fs');
fs.writeFileSync('p.txt', 'promise read');
fs.promises.readFile('p.txt', 'utf8').then((data) => {
  console.log(data);
});
