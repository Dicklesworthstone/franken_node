const os = require('os');
const h1 = os.hostname();
const h2 = os.hostname();
console.log(h1 === h2);
console.log(h1.length > 0);
console.log(!/\s/.test(h1) && !h1.includes('/'));
