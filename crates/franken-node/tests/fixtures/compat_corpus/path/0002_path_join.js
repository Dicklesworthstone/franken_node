const path = require('path');
console.log(path.join('a', 'b', '..', 'c'));
console.log(path.join('a', '..', '..', 'b'));
console.log(path.join('/x', 'y', '..', 'z'));
