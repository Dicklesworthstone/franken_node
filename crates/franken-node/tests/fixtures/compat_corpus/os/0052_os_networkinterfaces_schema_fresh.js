const os = require('os');
const ni1 = os.networkInterfaces();
const ni2 = os.networkInterfaces();
console.log(ni1 !== ni2);
const entries = Object.entries(ni1);
const keysValid = entries.every(([k]) => typeof k === 'string' && k.length > 0);
const valsValid = entries.every(([, list]) =>
  Array.isArray(list) && list.every((i) =>
    typeof i.address === 'string' &&
    typeof i.netmask === 'string' &&
    typeof i.mac === 'string' &&
    typeof i.internal === 'boolean'
  )
);
console.log(keysValid);
console.log(valsValid);
