const path = require('path');
console.log(path.relative('/', '/a/b/c'));
console.log(path.relative('/a/b/c', '/'));
console.log(JSON.stringify(path.relative('/', '/')));
