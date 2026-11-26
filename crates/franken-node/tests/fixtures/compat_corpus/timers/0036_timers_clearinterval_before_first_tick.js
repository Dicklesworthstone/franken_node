let ticks = 0;
const iv = setInterval(() => {
  ticks++;
}, 10);
clearInterval(iv);
setTimeout(() => {
  console.log('ticks-after-immediate-clear:' + ticks);
}, 35);
