const path = require('path');
console.log(path.win32.basename('C:\\temp\\myfile.html'));
console.log(path.win32.basename('C:/temp/other.html'));
console.log(path.win32.basename('C:\\temp\\page.html', '.html'));
