const b = Buffer.alloc(4);
console.log(b.writeInt8(-128, 0), b.writeInt8(-1, 1), b.writeInt8(0, 2), b.writeInt8(127, 3));
console.log(b.readInt8(0), b.readInt8(1), b.readInt8(2), b.readInt8(3));
console.log(b.toString('hex'));
