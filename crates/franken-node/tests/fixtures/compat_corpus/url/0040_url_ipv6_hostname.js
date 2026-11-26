const u1 = new URL('http://[::1]:8080/health');
const u2 = new URL('http://[2001:0db8:0000:0000:0000:0000:0000:0001]/idx');
console.log(u1.hostname, u1.host, u1.port, u1.origin);
console.log(u2.hostname, u2.href);
