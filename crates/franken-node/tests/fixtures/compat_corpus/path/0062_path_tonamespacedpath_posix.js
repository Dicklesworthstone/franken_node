const path = require('path');
console.log(path.posix.toNamespacedPath('/a/b/c'));
console.log(path.posix.toNamespacedPath('rel/path'));
console.log(JSON.stringify(path.posix.toNamespacedPath('')));
