const b = Buffer.from('aGVsbG8gd29ybGQ=', 'base64');
console.log(b.toString('utf8'));
console.log(Buffer.from('hello world').toString('base64'));
