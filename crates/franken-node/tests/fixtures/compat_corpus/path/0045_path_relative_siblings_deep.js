const path = require('path');
console.log(path.relative('/a/b', '/a/c'));
console.log(path.relative('/a/b/c', '/a/d/e/f'));
console.log(path.relative('/x/y/z', '/x/y'));
console.log(path.relative('/x/y', '/x/y/z/w'));
