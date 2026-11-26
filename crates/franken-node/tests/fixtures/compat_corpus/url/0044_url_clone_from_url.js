const a = new URL('https://ex.com/a?x=1#h');
const b = new URL(a);
b.pathname = '/b';
b.searchParams.set('x', '2');
console.log(a.href);
console.log(b.href);
