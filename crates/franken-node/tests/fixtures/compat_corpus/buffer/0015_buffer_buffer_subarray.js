const b = Buffer.from('abcdef');
const s = b.subarray(2, 5);
b[2] = 0x5a;
console.log(s.toString('utf8'));
console.log(s.length);
