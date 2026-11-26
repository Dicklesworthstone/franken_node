const b1 = Buffer.alloc(3, 0x2e);
const n1 = b1.write('a€');
const b2 = Buffer.alloc(4, 0x2e);
const n2 = b2.write('a€');
console.log(n1, b1.toString('hex'));
console.log(n2, b2.toString('hex'));
