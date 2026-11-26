const orig = Buffer.from('hello');
const copy = Buffer.from(orig);
copy[0] = 0x48;
console.log(orig.toString('utf8'));
console.log(copy.toString('utf8'));
console.log(orig.equals(copy));
