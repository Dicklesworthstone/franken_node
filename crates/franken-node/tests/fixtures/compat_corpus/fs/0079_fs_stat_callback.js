const fs = require('fs');
const path = require('path');
const dir = fs.mkdtempSync('case0079-');
const file = path.join(dir, 'item.txt');
fs.writeFileSync(file, '1234567');
fs.stat(file, (err, st) => {
  console.log(err === null, st.isFile(), st.isDirectory(), st.size);
  fs.stat(path.join(dir, 'nope.txt'), (err2) => {
    try {
      console.log(err2 !== null, err2.code);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
