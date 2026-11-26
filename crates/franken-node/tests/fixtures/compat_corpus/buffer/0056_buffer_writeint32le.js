const b = Buffer.alloc(12);
b.writeInt32LE(-2147483648, 0);
b.writeInt32LE(-1, 4);
b.writeInt32LE(2147483647, 8);
console.log(b.toString('hex'));
console.log(b.readInt32LE(0), b.readInt32LE(4), b.readInt32LE(8));
