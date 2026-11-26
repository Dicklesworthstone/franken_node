const {addAbortListener} = require('events');
const ac1 = new AbortController();
let fired1 = 0;
addAbortListener(ac1.signal, () => { fired1++; });
ac1.abort();
ac1.abort();

const ac2 = new AbortController();
let fired2 = 0;
const disp = addAbortListener(ac2.signal, () => { fired2++; });
disp[Symbol.dispose]();
ac2.abort();

console.log('fired1:' + fired1);
console.log('fired2:' + fired2);
