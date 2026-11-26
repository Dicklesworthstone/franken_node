const path = require('path');
console.log(path.win32.relative('C:\\a\\b', 'C:\\a\\c\\d'));
console.log(path.win32.relative('C:\\a\\b', 'D:\\x\\y'));
console.log(JSON.stringify(path.win32.relative('C:\\a\\b', 'C:\\a\\b')));
