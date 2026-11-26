const path = require('path');
console.log(JSON.stringify(path.extname('dir.ext/file')));
console.log(JSON.stringify(path.extname('/a.b/c.d/plain')));
console.log(JSON.stringify(path.extname('a.txt/')));
console.log(JSON.stringify(path.extname('/dir/sub.d///')));
