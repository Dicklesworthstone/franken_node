const u1 = new URL('  https://ex.com/a\tb\nc  ');
const u2 = new URL('\thttp://ex.com/\r\npath');
console.log(u1.href);
console.log(u2.pathname, u2.href);
