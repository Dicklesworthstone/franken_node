const u = new URL('https://example.com/a');
u.username = 'alice smith';
u.password = 'p@ss:1/2';
console.log(u.username);
console.log(u.password);
console.log(u.href);
