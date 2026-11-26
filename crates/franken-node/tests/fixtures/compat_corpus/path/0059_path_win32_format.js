const path = require('path');
console.log(path.win32.format({ dir: 'C:\\a\\b', base: 'file.txt' }));
console.log(path.win32.format({ root: 'C:\\', name: 'autoexec', ext: '.bat' }));
console.log(path.win32.format({ dir: 'C:\\', base: 'boot.ini' }));
