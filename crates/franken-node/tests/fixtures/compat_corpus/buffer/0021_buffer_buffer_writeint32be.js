const b = Buffer.alloc(4);
b.writeInt32BE(-2, 0);
console.log(b.toString('hex'));
console.log(b.readInt32BE(0));
console.log(b.readUInt32BE(0));
