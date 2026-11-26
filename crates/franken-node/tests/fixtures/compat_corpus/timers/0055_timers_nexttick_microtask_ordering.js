const order = [];
setTimeout(() => {
  order.push('timeout');
  console.log(order.join(','));
}, 0);
Promise.resolve().then(() => order.push('promise'));
queueMicrotask(() => order.push('microtask'));
process.nextTick(() => order.push('nextTick'));
order.push('sync');
