const path = require('path');
console.log(JSON.stringify(path.relative('/a/b', '/a/b')));
console.log(JSON.stringify(path.relative('/a/b/', '/a/b')));
