const a = Buffer.from('foo'), b = Buffer.from('bar'), c = Buffer.from('baz');
const all = Buffer.concat([a, b, c]);
console.log(all.toString('utf8'));
console.log(Buffer.concat([a, b], 4).toString('utf8'));
console.log(all.length);
