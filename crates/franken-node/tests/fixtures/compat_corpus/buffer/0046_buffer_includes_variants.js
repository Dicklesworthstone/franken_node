const b = Buffer.from('hello world');
console.log(b.includes(0x77));
console.log(b.includes(0x7a));
console.log(b.includes(Buffer.from('wor')));
console.log(b.includes('world', -5));
console.log(b.includes('world', -4));
console.log(b.includes('6f72', 0, 'hex'));
