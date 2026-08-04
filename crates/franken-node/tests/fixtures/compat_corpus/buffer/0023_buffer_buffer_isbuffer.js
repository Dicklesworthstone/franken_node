console.log(Buffer.isBuffer(Buffer.from('x')));
console.log(Buffer.isBuffer(new Uint8Array(2)));
console.log(Buffer.isBuffer('str'));
