const p = new URLSearchParams('a=b+c&d=%2B&e=x%20y');
console.log(p.get('a'), p.get('d'), p.get('e'));
