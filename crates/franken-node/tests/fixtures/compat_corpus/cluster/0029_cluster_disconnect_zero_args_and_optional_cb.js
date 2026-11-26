const cluster = require('cluster');
const order = [];
cluster.disconnect(function () {
  order.push('cb-argc:' + arguments.length);
  console.log(order.join(','));
});
cluster.disconnect();
order.push('sync-done');
