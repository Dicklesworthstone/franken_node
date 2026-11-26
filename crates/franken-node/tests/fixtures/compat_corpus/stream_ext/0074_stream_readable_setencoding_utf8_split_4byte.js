const { Readable } = require('stream');
const r = new Readable({ read() {} });
r.setEncoding('utf8');
const rocket = Buffer.from([0xf0, 0x9f, 0x9a, 0x80]); // U+1F680
r.push(rocket.subarray(0, 2));
r.push(rocket.subarray(2, 4));
r.push(null);
let acc = '';
r.on('data', (c) => { acc += c; });
r.on('end', () => {
  console.log(acc.length);
  console.log(acc.codePointAt(0).toString(16));
});
