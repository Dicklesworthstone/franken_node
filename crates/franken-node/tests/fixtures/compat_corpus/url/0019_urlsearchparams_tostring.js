const p = new URLSearchParams();
p.append('q', 'a b&c=d');
p.append('u', '\u4e2d');
console.log(p.toString());
