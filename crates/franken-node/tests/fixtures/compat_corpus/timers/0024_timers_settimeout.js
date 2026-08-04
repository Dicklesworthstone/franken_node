const order = [];
setTimeout(() => { order.push('d30'); console.log(order.join(',')); }, 30);
setTimeout(() => { order.push('d20'); }, 20);
setTimeout(() => { order.push('d10'); }, 10);
