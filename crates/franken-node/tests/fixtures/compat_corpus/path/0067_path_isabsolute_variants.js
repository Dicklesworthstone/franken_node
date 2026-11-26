const path = require('path');
console.log(path.isAbsolute('/'));
console.log(path.isAbsolute('//server/share'));
console.log(path.isAbsolute('.'));
console.log(path.isAbsolute('..'));
console.log(path.isAbsolute(''));
console.log(path.isAbsolute('a/b'));
