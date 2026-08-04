const qs = require('querystring');
console.log(qs.parse('msg=hello+world+again').msg);
console.log(qs.parse('two+part=v')['two part']);
