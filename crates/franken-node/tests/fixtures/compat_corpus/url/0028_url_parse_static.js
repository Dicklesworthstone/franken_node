const u1 = URL.parse('https://example.com/a?x=1');
const u2 = URL.parse('../b', 'https://example.com/x/y/z');
const u3 = URL.parse('not a url');
const u4 = URL.parse('/rel', 'bad-base');
console.log(u1 instanceof URL, u1.href);
console.log(u2 instanceof URL, u2.href);
console.log(u3, u4);
