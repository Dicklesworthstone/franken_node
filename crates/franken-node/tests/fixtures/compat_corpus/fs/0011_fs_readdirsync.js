const fs = require('fs');
fs.mkdirSync('sub');
fs.writeFileSync('plain.txt', 'x');
const ents = fs.readdirSync('.', { withFileTypes: true });
ents.sort((x, y) => (x.name < y.name ? -1 : 1));
for (const e of ents) console.log(e.name + ':' + (e.isFile() ? 'file' : 'dir'));
