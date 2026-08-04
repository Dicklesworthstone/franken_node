const fs = require('fs');
fs.promises.mkdir('pdir')
  .then(() => fs.promises.writeFile('pdir/one.txt', '1'))
  .then(() => fs.promises.writeFile('pdir/two.txt', '2'))
  .then(() => fs.promises.readdir('pdir'))
  .then((names) => console.log(names.sort().join(',')));
