const order = [];
setTimeout(() => {
  order.push('omitted');
  if (order.length === 2) console.log(order.join(','));
});
setTimeout(() => {
  order.push('undef');
  if (order.length === 2) console.log(order.join(','));
}, undefined);
console.log('sync');
