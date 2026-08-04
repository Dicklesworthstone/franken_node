const order = [];
setTimeout(() => { order.push('late'); console.log(order.join(',')); }, 20);
setTimeout(() => { order.push('early'); }, 0);
