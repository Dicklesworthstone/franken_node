const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0084-');
const file = path.join(dir, 'app.txt');
fs.writeFileSync(file, 'start-');
fs.appendFile(file, 'middle-', (err1) => {
  fs.appendFile(file, 'end', (err2) => {
    try {
      console.log(err1 === null, err2 === null);
      console.log(fs.readFileSync(file, 'utf8'));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
