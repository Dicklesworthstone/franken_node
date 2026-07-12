let fired = false;
const t = setTimeout(() => { fired = true; }, 10);
clearTimeout(t);
setTimeout(() => {
  console.log('cancelled-fired:' + fired);
}, 30);
