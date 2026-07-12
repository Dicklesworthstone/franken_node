const s = 'héllo€';
console.log(Buffer.byteLength(s, 'utf8'));
console.log(Buffer.byteLength(s, 'latin1'));
console.log(s.length);
