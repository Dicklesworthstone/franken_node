const order = [];
setTimeout(() => {
  order.push('macro');
  console.log(order.join(','));
}, 0);
queueMicrotask(() => { order.push('micro'); });
console.log('sync');
