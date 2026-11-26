const pat = Buffer.from([0xaa, 0xbb, 0xcc]);
const b = Buffer.alloc(8, pat);
pat[0] = 0x00;
console.log(b.toString('hex'));
console.log(b.length);
