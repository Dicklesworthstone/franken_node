const order = [];
setTimeout(() => {
  order.push('timeout');
  console.log(order.join(','));
}, 10);
setImmediate(() => {
  order.push('immediate');
});
queueMicrotask(() => {
  order.push('m1');
  queueMicrotask(() => {
    order.push('m2');
    queueMicrotask(() => {
      order.push('m3');
    });
  });
});
order.push('sync');
