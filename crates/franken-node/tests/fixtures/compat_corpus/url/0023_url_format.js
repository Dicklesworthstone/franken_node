const url = require('url');
console.log(url.format({ protocol: 'https', hostname: 'example.com', pathname: '/pth', search: 'x=1' }));
console.log(url.format({ protocol: 'http:', hostname: 'h.test', pathname: '/a' }));
