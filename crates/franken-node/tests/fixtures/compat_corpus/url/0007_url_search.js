const u = new URL('http://example.com/p?a=1&b=2#sec-2');
console.log(u.search, u.hash);
const v = new URL('http://example.com/p');
console.log(JSON.stringify(v.search), JSON.stringify(v.hash));
