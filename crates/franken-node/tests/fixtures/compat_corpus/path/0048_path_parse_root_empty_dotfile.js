const path = require('path');
console.log(JSON.stringify(path.parse('/')));
console.log(JSON.stringify(path.parse('')));
console.log(JSON.stringify(path.parse('/a/.bashrc')));
console.log(JSON.stringify(path.parse('/a/.env.local')));
