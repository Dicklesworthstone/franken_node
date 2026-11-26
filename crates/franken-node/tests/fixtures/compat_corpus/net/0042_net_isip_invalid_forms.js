const net = require('net');
console.log(
  net.isIP('127.0.0.1/24'),
  net.isIP('[::1]'),
  net.isIP('localhost'),
  net.isIP('1::2::3'),
  net.isIP(' 127.0.0.1')
);
