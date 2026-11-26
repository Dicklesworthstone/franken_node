const path = require('path');
const samples = ['/usr/local/bin/node', 'src/index.ts', '/', '/etc/hosts', 'README'];
for (const s of samples) {
  console.log(path.format(path.parse(s)) === s, path.format(path.parse(s)));
}
