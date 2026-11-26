const path = require('path');
console.log(path.win32.basename('C:\\dir\\index.html', '.html'));
console.log(path.win32.basename('C:/dir/app.js', '.js'));
console.log(path.win32.basename('C:\\dir\\app.js', '.ts'));
console.log(JSON.stringify(path.win32.basename('C:\\')));
