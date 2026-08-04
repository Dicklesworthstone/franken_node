const b = Buffer.alloc(3);
b.writeUInt8(0xff, 0);
b.writeUInt8(1, 2);
console.log(b.readUInt8(0));
console.log(b.toString('hex'));
