const b = Buffer.alloc(11);
b.writeIntBE(-1000, 0, 3);
b.writeIntLE(-1000, 3, 3);
b.writeIntBE(-109951162777, 6, 5);
console.log(b.toString('hex'));
console.log(b.readIntBE(0, 3), b.readIntLE(3, 3), b.readIntBE(6, 5));
