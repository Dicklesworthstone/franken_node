const z1 = Buffer.alloc(0);
const z2 = Buffer.alloc(0, 'abc');
const e1 = Buffer.alloc(4, '');
console.log(z1.length, z1.toString('hex'));
console.log(z2.length, Buffer.isBuffer(z2));
console.log(e1.length, e1.toString('hex'));
