const path = require('path');
console.log(path.format({ root: '/a', base: 'b.txt' }));
console.log(path.format({ root: '/a/', base: 'b.txt' }));
console.log(path.format({ root: '/a', name: 'b', ext: '.txt' }));
