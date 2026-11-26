const u = new URL('https://example.com:8443/api/v1?k=v');
u.hostname = 'sub.example.org';
console.log(u.hostname, u.host, u.port);
console.log(u.href);
