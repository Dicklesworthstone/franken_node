const path = require('path');
console.log(JSON.stringify(path.extname('.bashrc')));
console.log(JSON.stringify(path.extname('/home/.hidden')));
console.log(path.extname('.config.json'));
