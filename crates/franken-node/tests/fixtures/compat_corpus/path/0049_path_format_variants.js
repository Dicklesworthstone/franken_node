const path = require('path');
console.log(JSON.stringify(path.format({})));
console.log(JSON.stringify(path.format({ root: '/', base: 'a.txt' })));
console.log(JSON.stringify(path.format({ dir: '/a/b', name: 'c', ext: '.js' })));
console.log(JSON.stringify(path.format({ dir: '/a/b', name: 'c', ext: 'js' })));
