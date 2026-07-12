const path = require('path');
console.log(path.isAbsolute(path.resolve('a')));
console.log(path.isAbsolute(path.resolve('a', 'b/c')));
console.log(path.isAbsolute(path.resolve()));
