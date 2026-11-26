const u = new URL('file:///var/tmp/report.json');
console.log(u.protocol);
console.log(JSON.stringify(u.hostname));
console.log(u.pathname);
console.log(u.origin);
console.log(u.href);
