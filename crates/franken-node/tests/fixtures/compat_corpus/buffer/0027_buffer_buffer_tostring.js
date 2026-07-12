const b = Buffer.from([251, 255, 190]);
console.log(b.toString('base64'));
console.log(b.toString('base64url'));
console.log(Buffer.from('-_-_', 'base64url').toString('hex'));
