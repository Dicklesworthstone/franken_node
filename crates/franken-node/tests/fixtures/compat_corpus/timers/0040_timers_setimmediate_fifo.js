const order = [];
setImmediate(() => { order.push('i1'); });
setImmediate(() => { order.push('i2'); });
setImmediate(() => {
  order.push('i3');
  console.log(order.join(','));
});
