const u = new URL('http://example.com/path?a=1');
u.protocol = 'https:';
console.log(u.protocol, u.origin, u.href);
u.protocol = 'http';
console.log(u.protocol, u.origin, u.href);
