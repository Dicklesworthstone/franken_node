const b = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]);
b.swap16();
console.log(b.toString('hex'));
b.swap32();
console.log(b.toString('hex'));
