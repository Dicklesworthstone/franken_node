const b = Buffer.from('A\u0141\u00e9', 'ascii');
console.log(b.toString('hex'));
console.log(b.toString('ascii'));
console.log(Buffer.from([0x41, 0xc1, 0x80]).toString('ascii'));
