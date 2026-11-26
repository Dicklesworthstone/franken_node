const path = require('path');
console.log(path.win32.extname('C:\\dir\\file.txt'));
console.log(path.win32.extname('C:/dir.d/plain'));
console.log(path.win32.extname('C:\\dir\\archive.tar.gz'));
console.log(JSON.stringify(path.win32.extname('C:\\dir\\a.txt\\')));
