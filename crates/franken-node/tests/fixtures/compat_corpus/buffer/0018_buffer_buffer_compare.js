const a = Buffer.from('abc'), b = Buffer.from('abd');
console.log(Buffer.compare(a, b));
console.log(Buffer.compare(b, a));
console.log(Buffer.compare(a, Buffer.from('abc')));
console.log(a.compare(b));
