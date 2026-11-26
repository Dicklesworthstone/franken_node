const u = new URL('https://ex.com/a?q=hi there&x=<1>&y="2"');
console.log(u.search);
console.log(u.href);
