const u = new URL('http://a.com/1');
u.href = 'https://b.com:8443/2/3?k=v#frag';
console.log(u.protocol, u.host, u.pathname, u.search, u.hash);
console.log(u.href);
