const sp = new URLSearchParams({ x: '1', y: 'hello world', z: 'a&b' });
console.log(sp.toString());
console.log(sp.get('x'), sp.get('y'), sp.get('z'));
