const p = new URLSearchParams('a=1&b=3&a=2');
p.set('a', '9');
console.log(p.toString());
p.set('c', 'new');
console.log(p.toString());
