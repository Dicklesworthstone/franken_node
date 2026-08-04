const b = Buffer.alloc(2);
b.writeUInt16LE(0x1234, 0);
console.log(b.toString('hex'));
console.log(b.readUInt16LE(0));
console.log(b.readUInt16BE(0));
