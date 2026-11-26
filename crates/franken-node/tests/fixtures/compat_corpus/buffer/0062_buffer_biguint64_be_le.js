const b = Buffer.alloc(16);
b.writeBigUInt64BE(12345678901234567890n, 0);
b.writeBigUInt64LE(18446744073709551615n, 8);
console.log(b.toString('hex'));
console.log(b.readBigUInt64BE(0).toString());
console.log(b.readBigUInt64LE(8).toString());
