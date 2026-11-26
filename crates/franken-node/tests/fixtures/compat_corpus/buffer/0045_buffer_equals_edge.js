console.log(Buffer.alloc(0).equals(Buffer.alloc(0)));
console.log(Buffer.from('ab').equals(Buffer.from('abc')));
console.log(Buffer.from([1, 2, 3]).equals(new Uint8Array([1, 2, 3])));
console.log(Buffer.from([1, 2, 3]).equals(new Uint8Array([1, 2, 4])));
