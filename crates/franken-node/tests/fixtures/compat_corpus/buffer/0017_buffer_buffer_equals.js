const a = Buffer.from('abc');
console.log(a.equals(Buffer.from('abc')));
console.log(a.equals(Buffer.from('abd')));
console.log(a.equals(Buffer.from('ab')));
