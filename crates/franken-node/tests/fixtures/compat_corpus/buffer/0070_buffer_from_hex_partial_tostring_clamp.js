console.log(Buffer.from('61626', 'hex').toString('hex'));
console.log(Buffer.from('61zz62', 'hex').toString('hex'));
const b = Buffer.from('hello');
console.log(b.toString('utf8', 1, 999));
console.log(JSON.stringify(b.toString('utf8', 4, 2)));
console.log(JSON.stringify(b.toString('utf8', -4, -1)));
