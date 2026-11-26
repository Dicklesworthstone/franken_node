const b = Buffer.alloc(16);
b.writeBigInt64BE(-9007199254740993n, 0);
b.writeBigInt64LE(-123456789012345n, 8);
console.log(b.toString('hex'));
console.log(b.readBigInt64BE(0).toString());
console.log(b.readBigInt64LE(8).toString());
