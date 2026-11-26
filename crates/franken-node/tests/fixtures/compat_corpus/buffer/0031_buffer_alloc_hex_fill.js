const b1 = Buffer.alloc(6, 'aabb', 'hex');
const b2 = Buffer.alloc(5, '010203', 'hex');
console.log(b1.toString('hex'));
console.log(b2.toString('hex'));
console.log(b1.length, b2.length);
