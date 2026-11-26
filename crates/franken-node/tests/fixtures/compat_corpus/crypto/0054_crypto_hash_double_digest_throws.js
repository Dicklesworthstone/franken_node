const crypto = require('crypto');
const h = crypto.createHash('sha256').update('once');
const first = h.digest('hex');
let doubleDigestThrew = false;
try {
  h.digest('hex');
} catch (e) {
  doubleDigestThrew = e instanceof Error;
}
let updateAfterThrew = false;
try {
  h.update('more');
} catch (e) {
  updateAfterThrew = e instanceof Error;
}
console.log(first.length === 64);
console.log(doubleDigestThrew, updateAfterThrew);
