const path = require('path');
const p = path.parse('/home/user/dir/file.txt');
console.log(p.root, p.dir, p.base, p.ext, p.name);
