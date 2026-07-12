const src = Buffer.from('abcdef');
const dst = Buffer.from('123456');
const n = src.copy(dst, 1, 2, 5);
console.log(dst.toString('utf8'));
console.log(n);
