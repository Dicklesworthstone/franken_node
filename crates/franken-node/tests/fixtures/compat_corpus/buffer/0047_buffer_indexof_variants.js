const b = Buffer.from('ababa');
console.log(b.indexOf('ba', -3));
console.log(b.indexOf('ba', -1));
console.log(b.indexOf(''));
console.log(b.indexOf('', 2));
console.log(b.indexOf('', 99));
console.log(b.indexOf(Buffer.from('aba'), 1));
console.log(b.indexOf('6261', 0, 'hex'));
