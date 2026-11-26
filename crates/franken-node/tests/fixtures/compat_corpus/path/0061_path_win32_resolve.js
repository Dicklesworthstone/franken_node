const path = require('path');
console.log(path.win32.resolve('C:\\a', '..\\b'));
console.log(path.win32.resolve('C:\\a\\b', 'D:\\c', 'd'));
console.log(path.win32.resolve('C:\\a\\b', '\\c\\d'));
