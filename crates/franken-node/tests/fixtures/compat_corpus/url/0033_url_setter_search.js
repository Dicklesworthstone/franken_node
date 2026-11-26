const u = new URL('https://example.com/p?old=1');
u.search = 'k=v&m=2';
console.log(u.search, u.searchParams.get('k'), u.searchParams.get('m'));
u.search = '?z=9';
console.log(u.search, u.searchParams.get('z'), u.searchParams.has('k'));
u.search = '';
console.log(JSON.stringify(u.search), u.href);
