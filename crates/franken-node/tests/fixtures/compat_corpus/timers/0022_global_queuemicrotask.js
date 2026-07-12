const order = [];
queueMicrotask(() => { order.push('m1'); });
queueMicrotask(() => { order.push('m2'); });
queueMicrotask(() => { console.log(order.join(',')); });
console.log('sync-first');
