const crypto = require('crypto');
const key = Buffer.alloc(32, 1), iv = Buffer.alloc(16, 1);
const c = crypto.createCipheriv('aes-256-cbc', key, iv);
const ct = Buffer.concat([c.update('payload', 'utf8'), c.final()]);
try {
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 2), iv);
  Buffer.concat([d.update(ct), d.final()]);
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof Error);
}
