const net=require('net');
console.log(net.isIPv6('::1'),net.isIPv6('fe80::1'),net.isIPv6('127.0.0.1'));
