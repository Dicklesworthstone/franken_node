const path = require('path');
console.log(path.normalize('/foo/bar//baz/asdf/quux/..'));
console.log(path.normalize('a/./b//c'));
