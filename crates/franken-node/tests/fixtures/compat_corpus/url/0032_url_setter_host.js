const u = new URL('http://example.com:8080/p');
u.host = 'other.test:9090';
console.log(u.hostname, u.port, u.host);
u.host = 'plain.test';
console.log(u.hostname, JSON.stringify(u.port), u.host, u.href);
