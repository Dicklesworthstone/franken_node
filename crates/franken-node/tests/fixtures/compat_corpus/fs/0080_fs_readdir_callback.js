const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0080-');
fs.writeFileSync(path.join(dir, 'a.txt'), '1');
fs.writeFileSync(path.join(dir, 'b.txt'), '2');
fs.mkdirSync(path.join(dir, 'sub'));
fs.readdir(dir, (err, names) => {
  console.log(err === null, names.slice().sort().join(','));
  fs.readdir(dir, { withFileTypes: true }, (err2, dirents) => {
    try {
      const tagged = dirents.map((d) => `${d.name}:${d.isFile() ? 'F' : 'D'}`).sort();
      console.log(err2 === null, tagged.join(','));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
