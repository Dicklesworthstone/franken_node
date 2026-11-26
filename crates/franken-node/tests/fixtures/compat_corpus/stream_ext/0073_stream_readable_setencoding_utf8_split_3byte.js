const { Readable } = require('stream');
const r = new Readable({ read() {} });
r.setEncoding('utf8');
const euro = Buffer.from('€', 'utf8'); // [0xe2, 0x82, 0xac]
r.push(Buffer.from('A'));
r.push(euro.subarray(0, 1));
r.push(euro.subarray(1, 2));
r.push(euro.subarray(2, 3));
r.push(Buffer.from('Z'));
r.push(null);
let acc = '';
r.on('data', (c) => { acc += c; });
r.on('end', () => {
  console.log(acc);
  console.log(acc.length, acc.charCodeAt(1));
});
