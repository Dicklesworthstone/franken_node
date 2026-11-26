const http = require('http');
const required = ['DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
console.log('has-all:' + required.every((m) => http.METHODS.includes(m)));
