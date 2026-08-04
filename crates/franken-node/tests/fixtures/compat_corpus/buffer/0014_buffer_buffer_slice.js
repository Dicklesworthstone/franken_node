const b = Buffer.from('abcdef');
const s = b.slice(1, 4);
s[0] = 0x58;
console.log(b.toString('utf8'));
console.log(s.toString('utf8'));
