let n = 0;
const iv = setInterval(() => {
  n++;
  console.log('tick' + n);
  if (n === 3) {
    clearInterval(iv);
    console.log('stopped');
  }
}, 10);
