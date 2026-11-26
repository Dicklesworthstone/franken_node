const qs = require('querystring');
console.log(qs.stringify({ zero: 0, negZero: -0, neg: -42.5, big: 1e21 }));
