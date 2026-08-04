const p = new URLSearchParams('a=1');
p.append('a', '2');
p.append('b', '3');
console.log(p.toString());
