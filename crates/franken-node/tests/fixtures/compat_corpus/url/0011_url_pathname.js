const u = new URL('http://example.com/a');
u.pathname = '/b c';
u.hash = 'frag';
console.log(u.href);
u.hash = '';
console.log(u.href);
