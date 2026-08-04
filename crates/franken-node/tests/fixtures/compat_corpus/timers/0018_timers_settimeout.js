const order = [];
setTimeout(() => {
  order.push('string20');
  console.log(order.join(','));
}, '20');
setTimeout(() => { order.push('number5'); }, 5);
