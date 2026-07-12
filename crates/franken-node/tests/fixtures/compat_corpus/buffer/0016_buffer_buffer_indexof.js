const b = Buffer.from('hello hello');
console.log(b.indexOf('llo'));
console.log(b.indexOf('llo', 4));
console.log(b.indexOf(0x6c));
console.log(b.indexOf('zzz'));
console.log(b.includes('hello'));
console.log(b.includes('nope'));
