const os = require('os');
const h = os.homedir();
const u = os.userInfo();
console.log(h === os.homedir());
console.log(h === u.homedir);
console.log(h.length === 1 || !h.endsWith('/'));
