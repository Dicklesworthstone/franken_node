const b1 = Buffer.alloc(5).fill(0x41);
const b2 = Buffer.alloc(6).fill(0x2a, 1, 5);
const b3 = Buffer.alloc(4).fill(0x1ff);
console.log(b1.toString('utf8'));
console.log(b2.toString('hex'));
console.log(b3.toString('hex'));
