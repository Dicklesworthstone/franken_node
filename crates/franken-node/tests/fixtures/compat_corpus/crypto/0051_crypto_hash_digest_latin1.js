const crypto = require('crypto');
const raw = crypto.createHash('sha256').update('latin1-digest-check').digest();
const lat = crypto.createHash('sha256').update('latin1-digest-check').digest('latin1');
let match = lat.length === raw.length;
for (let i = 0; i < raw.length; i++) {
  if (lat.charCodeAt(i) !== raw[i]) match = false;
}
console.log(typeof lat, lat.length, match);
console.log(lat.charCodeAt(0), lat.charCodeAt(31));
