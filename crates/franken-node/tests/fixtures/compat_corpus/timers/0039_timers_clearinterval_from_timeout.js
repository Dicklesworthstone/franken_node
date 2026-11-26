let ticks = 0;
const iv = setInterval(() => {
  ticks++;
  if (ticks === 1) {
    setTimeout(() => {
      clearInterval(iv);
      console.log('cleared-from-timeout');
    }, 5);
  }
}, 50);
setTimeout(() => {
  console.log('final-ticks:' + ticks);
}, 130);
