const b = Buffer.alloc(8);
b.writeInt16LE(-1234, 0);
b.writeInt16BE(-1234, 2);
b.writeInt16LE(-32768, 4);
b.writeInt16BE(32767, 6);
console.log(b.toString('hex'));
console.log(b.readInt16LE(0), b.readInt16BE(2), b.readInt16LE(4), b.readInt16BE(6));
