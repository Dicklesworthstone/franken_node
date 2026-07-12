const path = require('path');
console.log(path.resolve('/x', '/y', 'z') === '/y/z');
console.log(path.resolve('ignored', '/a', 'b', '..', 'c') === '/a/c');
