const path = require('path');
console.log(JSON.stringify(path.basename('/a/foo.js', 'foo.js')));
console.log(JSON.stringify(path.basename('/')));
console.log(JSON.stringify(path.basename('///')));
console.log(JSON.stringify(path.basename('')));
