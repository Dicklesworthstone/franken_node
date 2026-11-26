const sp = new URLSearchParams('a=1&b=2&a=3');
sp.set('c', '4');
console.log(sp.toString());
sp.set('a', '9');
console.log(sp.toString());
