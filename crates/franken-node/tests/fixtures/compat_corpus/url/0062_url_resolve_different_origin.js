const u = new URL('https://other.org/x?k=1', 'http://base.com:8080/a/b');
console.log(u.origin);
console.log(u.href);
