const order = [];
setImmediate(() => {
  order.push('A');
  setImmediate(() => {
    order.push('C');
    console.log(order.join(','));
  });
});
setImmediate(() => { order.push('B'); });
