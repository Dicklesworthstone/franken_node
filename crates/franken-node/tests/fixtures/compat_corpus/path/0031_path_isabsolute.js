const path = require('path');
console.log(path.isAbsolute('/a/b'));
console.log(path.isAbsolute('a/b'));
console.log(path.isAbsolute('./a'));
console.log(path.isAbsolute(''));
