const net=require('net');
console.log(net.isIP('127.0.0.1'),net.isIP('::1'),net.isIP('not-an-ip'));
