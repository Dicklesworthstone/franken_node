const b = Buffer.alloc(8, 0x2e);
const n1 = b.write('hi', 2);
const n2 = b.write('world', 5, 2);
const n3 = b.write('6162', 0, 2, 'hex');
console.log(n1, n2, n3);
console.log(b.toString('utf8'));
