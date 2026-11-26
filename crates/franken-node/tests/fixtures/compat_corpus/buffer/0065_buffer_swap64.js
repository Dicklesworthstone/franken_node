const b = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
const ret = b.swap64();
console.log(ret === b);
console.log(b.toString('hex'));
