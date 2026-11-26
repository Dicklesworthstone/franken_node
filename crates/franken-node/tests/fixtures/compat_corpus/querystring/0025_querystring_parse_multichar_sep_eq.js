const qs = require('querystring');
console.log(JSON.stringify(qs.parse('a:=1||b:=2||a:=3', '||', ':=')));
console.log(JSON.stringify(qs.parse('k--v1::k2--v2', '::', '--')));
