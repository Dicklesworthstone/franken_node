const fs = require('fs');
fs.writeFileSync('plain.txt', 'data');
const st = fs.statSync('plain.txt');
console.log(st.isFile());
console.log(st.isDirectory());
