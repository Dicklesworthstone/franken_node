const order = [];
setTimeout(() => {
  order.push('timer');
  console.log(order.join(','));
}, 0);
Promise.resolve()
  .then(() => { order.push('then1'); })
  .then(() => { order.push('then2'); });
