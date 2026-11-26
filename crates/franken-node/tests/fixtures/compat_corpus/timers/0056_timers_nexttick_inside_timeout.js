const order = [];
setTimeout(() => {
  order.push('timer');
  queueMicrotask(() => order.push('micro'));
  process.nextTick(() => order.push('nextTick'));
}, 5);
setTimeout(() => {
  order.push('done');
  console.log(order.join(','));
}, 25);
