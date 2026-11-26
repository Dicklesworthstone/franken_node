const u1 = new URL('http://127.0.0.1:80/a');
const u2 = new URL('http://0x7f.1/a');
console.log(u1.hostname, u1.href);
console.log(u2.hostname, u2.href);
