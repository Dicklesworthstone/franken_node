const order = [];
let second;
setImmediate(() => {
  order.push('first');
  clearImmediate(second);
});
second = setImmediate(() => {
  order.push('second-should-not-run');
});
setImmediate(() => {
  order.push('third');
  console.log(order.join(','));
});
