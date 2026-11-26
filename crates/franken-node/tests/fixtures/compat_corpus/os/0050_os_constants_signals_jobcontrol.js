const os = require('os');
const s = os.constants.signals;
const expected = [
  s.SIGILL === 4,
  s.SIGTRAP === 5,
  s.SIGBUS === 7,
  s.SIGFPE === 8,
  s.SIGCONT === 18,
  s.SIGSTOP === 19,
  s.SIGTSTP === 20,
];
console.log(expected.every(Boolean));
console.log(new Set([s.SIGILL, s.SIGTRAP, s.SIGBUS, s.SIGFPE, s.SIGCONT, s.SIGSTOP, s.SIGTSTP]).size);
