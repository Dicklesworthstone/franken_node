const padded = Buffer.concat([Buffer.from([1, 2]), Buffer.from([3])], 6);
const empty = Buffer.concat([]);
const zero = Buffer.concat([Buffer.from('abc')], 0);
console.log(padded.toString('hex'), padded.length);
console.log(empty.length, Buffer.isBuffer(empty));
console.log(zero.length);
