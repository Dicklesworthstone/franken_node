const os = require('os');
const cpus = os.cpus();
const keys = ['user', 'nice', 'sys', 'idle', 'irq'];
const allValid = cpus.every((c) => {
  if (typeof c.model !== 'string' || typeof c.speed !== 'number' || c.speed < 0) return false;
  if (!c.times || typeof c.times !== 'object') return false;
  return keys.every((k) => typeof c.times[k] === 'number' && Number.isFinite(c.times[k]) && c.times[k] >= 0);
});
console.log(cpus.length >= 1);
console.log(allValid);
