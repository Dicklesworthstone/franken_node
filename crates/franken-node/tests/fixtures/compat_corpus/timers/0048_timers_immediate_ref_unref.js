const im = setImmediate(() => {
  console.log('immediate-fired');
});
console.log(im.hasRef());
console.log(im.unref() === im);
console.log(im.hasRef());
console.log(im.ref() === im);
console.log(im.hasRef());
