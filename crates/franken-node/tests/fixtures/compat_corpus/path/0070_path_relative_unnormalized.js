const path = require('path');
console.log(path.relative('/a/./b//c/..', '/a/b/../d/./e'));
console.log(JSON.stringify(path.relative('/a/b/../c', '/a/./c/')));
