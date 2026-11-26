const path = require('path');
console.log(JSON.stringify(path.normalize('a/b/../../')));
console.log(JSON.stringify(path.normalize('a/b/../..')));
console.log(JSON.stringify(path.normalize('a/b/../../../')));
console.log(JSON.stringify(path.normalize('a/b/../../..')));
