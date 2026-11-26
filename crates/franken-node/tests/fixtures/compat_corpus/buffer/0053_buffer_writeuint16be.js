const b = Buffer.alloc(4);
const r1 = b.writeUInt16BE(0x1234, 0);
const r2 = b.writeUInt16BE(0xffff, 2);
console.log(r1, r2);
console.log(b.toString('hex'));
console.log(b.readUInt16BE(0), b.readUInt16BE(2));
