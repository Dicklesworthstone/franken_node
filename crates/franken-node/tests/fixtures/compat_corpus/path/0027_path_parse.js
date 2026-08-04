const path = require('path');
const p = path.parse('dir/sub/file.tar.gz');
console.log(JSON.stringify(p.root), p.dir, p.base, p.ext, p.name);
