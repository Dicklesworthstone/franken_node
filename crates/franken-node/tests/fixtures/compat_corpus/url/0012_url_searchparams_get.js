const u = new URL('http://example.com/?a=1&b=two&a=3');
console.log(u.searchParams.get('a'), u.searchParams.get('b'));
console.log(u.searchParams.has('a'), u.searchParams.has('zz'), u.searchParams.get('zz') === null);
