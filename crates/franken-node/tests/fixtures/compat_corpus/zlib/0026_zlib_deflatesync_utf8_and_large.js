const zlib = require('zlib');
const utf8 = 'Deflate multibyte: Ω≈ç√∫˜µ ≤≥÷ 中文 🎉';
const rep = Buffer.from('repeat-block-0123456789-'.repeat(500));
const outUtf8 = zlib.inflateSync(zlib.deflateSync(utf8)).toString('utf8');
const cRep = zlib.deflateSync(rep);
const outRep = zlib.inflateSync(cRep);
console.log(outUtf8 === utf8);
console.log(outRep.equals(rep));
console.log(cRep.length < rep.length / 4);
