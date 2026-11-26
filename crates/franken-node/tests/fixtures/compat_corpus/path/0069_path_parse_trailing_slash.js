const path = require('path');
console.log(JSON.stringify(path.parse('/a/b/')));
console.log(JSON.stringify(path.parse('/a/b.d///')));
console.log(JSON.stringify(path.parse('rel/dir/')));
