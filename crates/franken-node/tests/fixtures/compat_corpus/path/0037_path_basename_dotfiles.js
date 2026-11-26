const path = require('path');
console.log(path.basename('/home/user/.bashrc'));
console.log(path.basename('/home/user/.env.local'));
console.log(path.basename('/home/user/.env.local', '.local'));
console.log(path.basename('/home/user/.bashrc', '.bashrc'));
