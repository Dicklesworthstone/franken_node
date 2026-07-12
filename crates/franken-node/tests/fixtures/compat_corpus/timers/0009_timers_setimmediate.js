console.log('sync1');
setImmediate(() => {
  console.log('immediate');
});
console.log('sync2');
