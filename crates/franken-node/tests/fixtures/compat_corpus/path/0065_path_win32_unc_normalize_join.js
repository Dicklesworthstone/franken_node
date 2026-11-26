const path = require('path');
console.log(path.win32.normalize('\\\\server\\share\\a\\..\\b'));
console.log(path.win32.join('\\\\server\\share', 'a', 'b', '..', 'c'));
console.log(path.win32.normalize('//server/share/x//y'));
