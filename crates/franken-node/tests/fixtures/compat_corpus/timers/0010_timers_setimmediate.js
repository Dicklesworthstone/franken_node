setTimeout(() => {
  const order = [];
  setImmediate(() => { order.push('immediate'); });
  setTimeout(() => {
    order.push('timeout');
    console.log(order.join(','));
  }, 0);
}, 5);
