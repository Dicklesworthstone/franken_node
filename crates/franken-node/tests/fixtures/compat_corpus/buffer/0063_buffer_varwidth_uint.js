const b = Buffer.alloc(12);
b.writeUIntBE(0x123456, 0, 3);
b.writeUIntLE(0x123456, 3, 3);
b.writeUIntBE(0x010203040506, 6, 6);
console.log(b.toString('hex'));
console.log(b.readUIntBE(0, 3), b.readUIntLE(3, 3), b.readUIntBE(6, 6));
