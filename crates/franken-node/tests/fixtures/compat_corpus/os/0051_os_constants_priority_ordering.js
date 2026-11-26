const os = require('os');
const p = os.constants.priority;
const ordered = [
  p.PRIORITY_HIGHEST,
  p.PRIORITY_HIGH,
  p.PRIORITY_ABOVE_NORMAL,
  p.PRIORITY_NORMAL,
  p.PRIORITY_BELOW_NORMAL,
  p.PRIORITY_LOW,
];
console.log(ordered.join(','));
let strictlyAsc = true;
for (let i = 1; i < ordered.length; i++) {
  if (!(ordered[i - 1] < ordered[i])) strictlyAsc = false;
}
console.log(strictlyAsc);
