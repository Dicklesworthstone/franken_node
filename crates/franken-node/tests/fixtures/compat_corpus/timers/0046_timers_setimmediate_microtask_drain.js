const order = [];
setTimeout(() => {
  order.push('late-timeout');
  console.log(order.join(','));
}, 20);
setImmediate(() => {
  order.push('immediate');
  queueMicrotask(() => {
    order.push('micro-from-immediate');
  });
});
