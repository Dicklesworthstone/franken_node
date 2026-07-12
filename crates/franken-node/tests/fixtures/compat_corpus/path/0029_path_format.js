const path = require('path');
console.log(path.format({ root: '/r/', dir: '/a', name: 'f', ext: '.txt', base: 'g.md' }));
console.log(path.format({ root: '/', name: 'f', ext: '.txt' }));
