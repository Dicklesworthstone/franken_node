const b = Buffer.alloc(8);
const r1 = b.writeUInt32BE(0xdeadbeef, 0);
const r2 = b.writeUInt32LE(0x01020304, 4);
console.log(r1, r2);
console.log(b.toString('hex'));
console.log(b.readUInt32BE(0), b.readUInt32LE(4));
