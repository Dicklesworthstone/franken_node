const path = require('path');
console.log(path.win32.isAbsolute('C:\\foo'));
console.log(path.win32.isAbsolute('\\\\server\\share'));
console.log(path.win32.isAbsolute('C:relative'));
console.log(path.win32.isAbsolute('foo\\bar'));
