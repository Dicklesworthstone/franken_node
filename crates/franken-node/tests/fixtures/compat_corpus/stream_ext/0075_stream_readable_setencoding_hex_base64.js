const { Readable } = require('stream');
const rHex = new Readable({ read() {} });
rHex.setEncoding('hex');
rHex.push(Buffer.from([0xde, 0xad]));
rHex.push(Buffer.from([0xbe, 0xef]));
rHex.push(null);

const rB64 = new Readable({ read() {} });
rB64.setEncoding('base64');
rB64.push(Buffer.from('Man'));
rB64.push(Buffer.from('!'));
rB64.push(null);

let hexOut = '';
let b64Out = '';
let done = 0;
function finish() {
  if (++done === 2) {
    console.log(hexOut);
    console.log(b64Out);
  }
}
rHex.on('data', (c) => { hexOut += c; });
rHex.on('end', finish);
rB64.on('data', (c) => { b64Out += c; });
rB64.on('end', finish);
