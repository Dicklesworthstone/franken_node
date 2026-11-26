const path = require('path');
console.log(path.win32.toNamespacedPath('C:\\a\\b'));
console.log(path.win32.toNamespacedPath('\\\\srv\\sh\\f.txt'));
console.log(path.win32.toNamespacedPath('C:\\a\\..\\b'));
