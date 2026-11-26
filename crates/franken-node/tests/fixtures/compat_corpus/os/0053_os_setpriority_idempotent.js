const os = require('os');
const cur = os.getPriority(0);
os.setPriority(0, cur);
console.log(os.getPriority(0) === cur);
os.setPriority(cur);
console.log(os.getPriority(0) === cur);
