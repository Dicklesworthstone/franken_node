const path = require('path');
console.log(JSON.stringify(path.dirname('/')));
console.log(JSON.stringify(path.dirname('///')));
console.log(JSON.stringify(path.dirname('///a')));
console.log(JSON.stringify(path.dirname('')));
console.log(JSON.stringify(path.dirname('.')));
