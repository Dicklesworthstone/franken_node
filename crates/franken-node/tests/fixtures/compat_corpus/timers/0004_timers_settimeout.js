const order = [];
setTimeout(() => { order.push('first'); }, 10);
setTimeout(() => { order.push('second'); }, 10);
setTimeout(() => { order.push('third'); console.log(order.join(',')); }, 10);
