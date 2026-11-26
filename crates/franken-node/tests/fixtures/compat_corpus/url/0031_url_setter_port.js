const u = new URL('https://example.com:8080/a');
u.port = '443';
console.log(JSON.stringify(u.port), u.host, u.href);
u.port = '9090';
console.log(JSON.stringify(u.port), u.host);
u.port = '';
console.log(JSON.stringify(u.port), u.href);
u.port = 'invalid';
console.log(JSON.stringify(u.port), u.href);
