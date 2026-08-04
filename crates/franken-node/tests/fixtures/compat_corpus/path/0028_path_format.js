const path = require('path');
console.log(path.format({ dir: '/a/b', base: 'c.txt' }));
console.log(path.format({ dir: 'rel/dir', base: 'f' }));
console.log(path.format({ name: 'file', ext: '.js' }));
