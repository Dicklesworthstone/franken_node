const os = require('os');
const u = os.userInfo();
console.log(typeof u.username);
console.log(typeof u.uid);
console.log(typeof u.homedir);
console.log(u.shell === null || typeof u.shell === 'string');
console.log(u.uid >= 0);
