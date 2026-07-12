const path = require('path');
console.log(path.normalize('a/b/'));
console.log(path.normalize('/x//y/'));
console.log(path.normalize('a/b'));
