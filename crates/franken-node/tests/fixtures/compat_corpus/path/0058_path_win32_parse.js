const path = require('path');
console.log(JSON.stringify(path.win32.parse('C:\\a\\b.txt')));
console.log(JSON.stringify(path.win32.parse('C:\\')));
console.log(JSON.stringify(path.win32.parse('dir\\sub\\index.js')));
