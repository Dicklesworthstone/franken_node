const path = require('path');
console.log(path.win32.relative('C:\\Foo\\Bar', 'c:\\foo\\baz'));
console.log(JSON.stringify(path.win32.relative('C:\\Users\\Dev', 'c:\\users\\dev')));
