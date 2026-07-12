let ran = false;
const im = setImmediate(() => { ran = true; });
clearImmediate(im);
setTimeout(() => {
  console.log('immediate-ran:' + ran);
}, 20);
