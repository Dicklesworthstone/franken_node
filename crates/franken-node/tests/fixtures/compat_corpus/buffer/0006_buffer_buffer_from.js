const ab = new ArrayBuffer(8);
new Uint8Array(ab).set([1, 2, 3, 4, 5, 6, 7, 8]);
const b = Buffer.from(ab, 2, 4);
console.log(b.toString('hex'));
console.log(b.length);
