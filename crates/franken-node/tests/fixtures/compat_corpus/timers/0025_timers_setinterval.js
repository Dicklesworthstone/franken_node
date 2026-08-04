let n = 0;
const iv = setInterval(() => {
  n++;
  if (n === 3) {
    clearInterval(iv);
    console.log('zero-interval-count:' + n);
  }
}, 0);
