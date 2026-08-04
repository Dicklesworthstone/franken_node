const fs = require('fs');
fs.writeFileSync('cb.txt', 'callback data');
fs.readFile('cb.txt', 'utf8', (err, data) => {
  console.log(err === null);
  console.log(data);
});
