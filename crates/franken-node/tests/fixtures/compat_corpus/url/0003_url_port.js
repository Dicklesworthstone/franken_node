const a = new URL('http://example.com:80/x');
const b = new URL('https://example.com:443/x');
console.log(JSON.stringify(a.port), a.host);
console.log(JSON.stringify(b.port), b.host);
