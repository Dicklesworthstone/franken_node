const { fileURLToPath } = require('url');
console.log(fileURLToPath('file:///a/b.txt'));
console.log(fileURLToPath('file:///dir/with%20space/f.txt'));
