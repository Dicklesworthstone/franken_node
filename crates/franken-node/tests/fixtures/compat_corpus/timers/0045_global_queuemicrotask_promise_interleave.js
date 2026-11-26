const order = [];
setTimeout(() => {
  order.push('timer');
  console.log(order.join(','));
}, 0);
queueMicrotask(() => order.push('q1'));
Promise.resolve().then(() => order.push('p1'));
queueMicrotask(() => order.push('q2'));
Promise.resolve().then(() => order.push('p2'));
order.push('sync');
