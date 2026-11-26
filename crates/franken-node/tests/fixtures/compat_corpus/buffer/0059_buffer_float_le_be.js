const b = Buffer.alloc(8);
b.writeFloatBE(1.5, 0);
b.writeFloatLE(-2.25, 4);
console.log(b.toString('hex'));
console.log(b.readFloatBE(0), b.readFloatLE(4));
