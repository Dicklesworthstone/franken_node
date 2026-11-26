const { isAscii, isUtf8 } = require('buffer');
console.log(
  isAscii(Buffer.from('hello')),
  isAscii(Buffer.from('héllo')),
  isAscii(Buffer.alloc(0)),
  isAscii(new Uint8Array([0, 127])),
  isAscii(new Uint8Array([128]))
);
console.log(
  isUtf8(Buffer.from('hello 🚀')),
  isUtf8(Buffer.from([0xff, 0xfe])),
  isUtf8(Buffer.from([0xc3, 0xa9])),
  isUtf8(Buffer.from([0xc3])),
  isUtf8(Buffer.alloc(0))
);
