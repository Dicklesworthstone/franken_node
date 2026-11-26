const os = require('os');
const u1 = os.userInfo();
const u2 = os.userInfo({ encoding: 'utf8' });
console.log(u1 !== u2);
console.log(Number.isInteger(u1.gid) && u1.gid >= 0);
console.log(u1.username === u2.username && u1.uid === u2.uid && u1.gid === u2.gid);
console.log(u1.homedir === u2.homedir && u1.shell === u2.shell);
