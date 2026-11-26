const u8 = new Uint8Array([10, 20, 30, 40]);
const b = Buffer.from(u8);
u8[0] = 99;
b[1] = 88;
console.log(Buffer.isBuffer(b), b.length);
console.log(Array.from(b).join(','));
console.log(Array.from(u8).join(','));
