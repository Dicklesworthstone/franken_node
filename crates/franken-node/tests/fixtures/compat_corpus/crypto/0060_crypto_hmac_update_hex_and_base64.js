const crypto = require('crypto');
const raw = Buffer.from('hello hmac encoding', 'utf8');
const ref = crypto.createHmac('sha256', 'k').update(raw).digest('hex');
const fromHex = crypto.createHmac('sha256', 'k').update(raw.toString('hex'), 'hex').digest('hex');
const fromB64 = crypto.createHmac('sha256', 'k').update(raw.toString('base64'), 'base64').digest('hex');
console.log(ref === fromHex, ref === fromB64);
console.log(ref);
