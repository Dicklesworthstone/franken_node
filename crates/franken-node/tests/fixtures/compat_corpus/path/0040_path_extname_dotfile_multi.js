const path = require('path');
console.log(JSON.stringify(path.extname('.a.b')));
console.log(JSON.stringify(path.extname('.gitignore')));
console.log(JSON.stringify(path.extname('.')));
console.log(JSON.stringify(path.extname('..')));
console.log(JSON.stringify(path.extname('..foo')));
