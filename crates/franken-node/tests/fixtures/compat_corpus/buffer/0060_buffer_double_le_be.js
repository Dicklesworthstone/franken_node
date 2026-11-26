const b = Buffer.alloc(16);
b.writeDoubleBE(3.141592653589793, 0);
b.writeDoubleLE(-0.125, 8);
console.log(b.toString('hex'));
console.log(b.readDoubleBE(0), b.readDoubleLE(8));
