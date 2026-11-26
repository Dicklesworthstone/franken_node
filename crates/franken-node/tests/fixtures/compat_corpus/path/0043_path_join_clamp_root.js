const path = require('path');
console.log(path.join('/', '..'));
console.log(path.join('/a', '..', '..', 'b'));
console.log(path.join('a', '..', '..', 'b'));
console.log(path.join('..', 'a', 'b'));
