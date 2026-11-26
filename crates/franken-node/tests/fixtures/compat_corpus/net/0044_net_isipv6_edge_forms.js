const net = require('net');
console.log(
  net.isIPv6('::'),
  net.isIPv6('::ffff:127.0.0.1'),
  net.isIPv6('127.0.0.1'),
  net.isIPv6('[::1]')
);
