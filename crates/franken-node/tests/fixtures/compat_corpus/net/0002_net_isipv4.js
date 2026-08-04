const net=require('net');
console.log(net.isIPv4('10.0.0.1'),net.isIPv4('::1'),net.isIPv4('999.1.1.1'));
