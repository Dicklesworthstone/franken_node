const s = '🚀日本語 café';
const b = Buffer.from(s, 'utf8');
console.log(s.length, b.length);
console.log(b.toString('hex'));
console.log(b.toString('utf8') === s);
