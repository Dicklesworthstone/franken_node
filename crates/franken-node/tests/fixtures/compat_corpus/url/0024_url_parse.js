const url = require('url');
const u = url.parse('http://example.com:8080/p/a?x=1&y=2#frag');
console.log(u.protocol, u.host, u.hostname, u.port);
console.log(u.pathname, u.search, u.hash);
