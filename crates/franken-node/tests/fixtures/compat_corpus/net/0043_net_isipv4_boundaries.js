const net = require('net');
console.log(
  net.isIPv4('0.0.0.0'),
  net.isIPv4('255.255.255.255'),
  net.isIPv4('::ffff:127.0.0.1'),
  net.isIPv4('01.02.03.04')
);
