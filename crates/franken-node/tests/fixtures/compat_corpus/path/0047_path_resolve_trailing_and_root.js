const path = require('path');
console.log(path.resolve('/a/b/'));
console.log(path.resolve('/a/b/', ''));
console.log(path.resolve('/'));
console.log(path.resolve('/a', '..', '..', 'c/'));
