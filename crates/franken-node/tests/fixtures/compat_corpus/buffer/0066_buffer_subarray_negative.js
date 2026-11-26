const b = Buffer.from('abcdef');
const sub = b.subarray(-4, -1);
const sl = b.slice(-3);
console.log(sub.toString('utf8'), sl.toString('utf8'));
sub[0] = 0x58;
console.log(b.toString('utf8'));
