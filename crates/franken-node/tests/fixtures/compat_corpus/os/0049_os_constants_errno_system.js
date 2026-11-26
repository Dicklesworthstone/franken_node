const os = require('os');
const e = os.constants.errno;
const vals = [
  e.ESRCH === 3,
  e.EINTR === 4,
  e.EIO === 5,
  e.ENOMEM === 12,
  e.EBUSY === 16,
  e.EMFILE === 24,
  e.ENOSPC === 28,
  e.EROFS === 30,
  e.ERANGE === 34,
];
console.log(vals.every(Boolean));
console.log(new Set([e.ESRCH, e.EINTR, e.EIO, e.ENOMEM, e.EBUSY, e.EMFILE, e.ENOSPC, e.EROFS, e.ERANGE]).size);
