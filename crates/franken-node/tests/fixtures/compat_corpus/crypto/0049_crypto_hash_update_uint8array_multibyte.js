const crypto = require('crypto');
const text = 'café-€-🚀';
const bytes = new Uint8Array(Buffer.from(text, 'utf8'));
const dStr = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
const dU8 = crypto.createHash('sha256').update(bytes).digest('hex');
console.log(dStr === dU8);
console.log(dStr);
