const net = require('net');
console.log(
  net.isIP('::'),
  net.isIP('::ffff:127.0.0.1'),
  net.isIP('fe80::1'),
  net.isIP('2001:db8::1')
);
