const order = [];
setTimeout(() => {
  order.push('timeout');
  console.log(order.join(','));
}, 0);
Promise.resolve('p').then((v) => { order.push('then:' + v); });
