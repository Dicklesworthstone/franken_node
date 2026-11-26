const orig = new URLSearchParams('a=1&b=2');
const clone = new URLSearchParams(orig);
clone.set('a', '99');
clone.append('c', '3');
console.log(orig.toString());
console.log(clone.toString());
