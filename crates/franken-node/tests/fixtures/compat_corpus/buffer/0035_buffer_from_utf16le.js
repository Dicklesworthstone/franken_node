const b = Buffer.from('ABC€', 'utf16le');
console.log(b.length);
console.log(b.toString('hex'));
console.log(b.toString('utf16le'));
