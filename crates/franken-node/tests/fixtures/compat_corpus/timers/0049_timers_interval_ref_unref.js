let n = 0;
const iv = setInterval(() => {
  n++;
  clearInterval(iv);
  console.log('interval-fired:' + n);
}, 5);
console.log(iv.hasRef());
console.log(iv.unref() === iv);
console.log(iv.hasRef());
console.log(iv.ref() === iv);
console.log(iv.hasRef());
