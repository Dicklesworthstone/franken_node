const p = new URLSearchParams('a=1&b=2&a=3');
p.delete('a');
console.log(p.toString(), p.has('a'), p.has('b'));
