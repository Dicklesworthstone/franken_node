const { fileURLToPath } = require('url');
console.log(fileURLToPath(new URL('file:///tmp/test%20file.txt')));
console.log(fileURLToPath(new URL('file:///dir/caf%C3%A9.txt')));
