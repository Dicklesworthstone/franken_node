const b1 = Buffer.alloc(6, 'YWJj', 'base64');
const b2 = Buffer.alloc(8, 'YWJj', 'base64');
console.log(b1.toString('utf8'));
console.log(b2.toString('utf8'));
console.log(b2.length);
