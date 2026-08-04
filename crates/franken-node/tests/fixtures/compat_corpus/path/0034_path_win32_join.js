const path = require('path');
console.log(JSON.stringify(path.win32.join('a', 'b', 'c')));
console.log(JSON.stringify(path.win32.join('a', '..', 'b')));
