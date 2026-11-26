const path = require('path');
console.log(path.win32.normalize('C:/a//b/../c'));
console.log(path.win32.normalize('C:\\a\\b\\..\\..\\d\\'));
console.log(path.win32.normalize('a/b/../c'));
console.log(path.win32.normalize(''));
