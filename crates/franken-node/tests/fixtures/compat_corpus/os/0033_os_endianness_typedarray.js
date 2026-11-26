const os = require('os');
const e1 = os.endianness();
const e2 = os.endianness();
const u16 = new Uint16Array([0x0102]);
const u8 = new Uint8Array(u16.buffer);
const detected = u8[0] === 0x02 ? 'LE' : 'BE';
console.log(e1 === e2);
console.log(e1 === detected);
