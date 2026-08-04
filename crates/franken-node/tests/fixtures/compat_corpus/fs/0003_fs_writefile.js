const fs = require('fs');
fs.writeFile('out.txt', 'written async', (err) => {
  console.log(err === null);
  console.log(fs.readFileSync('out.txt', 'utf8'));
});
