const path = require('path');
console.log(path.win32.dirname('C:\\a\\b\\c.txt'));
console.log(path.win32.dirname('C:\\'));
console.log(path.win32.dirname('C:\\foo'));
console.log(path.win32.dirname('C:/a/b/c'));
console.log(path.win32.dirname('plain.txt'));
