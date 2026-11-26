console.log(Buffer.byteLength(Buffer.from('hello')));
console.log(Buffer.byteLength(new Uint8Array(7)));
console.log(Buffer.byteLength(new ArrayBuffer(12)));
console.log(Buffer.byteLength(new Uint16Array(3)));
