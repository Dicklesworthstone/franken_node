const crypto = require('crypto');
const raw = 'franken-node-compat';
const b64 = Buffer.from(raw, 'utf8').toString('base64');
const h1 = crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
const h2 = crypto.createHash('sha256').update(b64, 'base64').digest('hex');
console.log(h1 === h2);
console.log(h1);
