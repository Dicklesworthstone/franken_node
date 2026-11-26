const order = [];
setTimeout(() => {
  order.push('slow');
  console.log(order.join(','));
}, 25.9);
setTimeout(() => {
  order.push('fast');
}, 5.4);
