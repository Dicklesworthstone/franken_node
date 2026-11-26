const path = require('path');
console.log(JSON.stringify(path.win32.parse('\\\\server\\share\\dir\\file.txt')));
console.log(path.win32.dirname('\\\\server\\share\\file.txt'));
console.log(path.win32.dirname('\\\\server\\share\\dir\\file.txt'));
