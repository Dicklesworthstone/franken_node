const crypto = require('crypto');
const h = crypto.createHash('sha256').update('partial');
const c = h.copy();
c.update('-more');
const dh = h.digest('hex'), dc = c.digest('hex');
console.log(dh);
console.log(dc);
console.log(dh === crypto.createHash('sha256').update('partial').digest('hex'));
