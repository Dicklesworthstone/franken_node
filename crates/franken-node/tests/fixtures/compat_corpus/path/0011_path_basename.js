const path = require('path');
console.log(path.basename('/foo/bar.txt', '.html'));
console.log(path.basename('bar', 'longer-than-name'));
