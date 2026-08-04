const fs = require('fs');
try {
  fs.unlinkSync('ghost.txt');
  console.log('no-throw');
} catch (e) {
  console.log(e.code);
}
