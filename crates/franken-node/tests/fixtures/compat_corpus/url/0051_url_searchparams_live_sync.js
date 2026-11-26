const u = new URL('https://ex.com/p?a=1');
u.searchParams.append('b', '2');
console.log(u.search, u.href);
u.searchParams.set('a', '10');
console.log(u.search, u.href);
u.searchParams.delete('a');
u.searchParams.delete('b');
console.log(JSON.stringify(u.search), u.href);
