const net=require('net');
const srv=net.createServer(sock=>{
  console.log('remote-is-loopback:'+String(sock.remoteAddress).includes('127.0.0.1'));sock.end();srv.close();
});
srv.listen(0,'127.0.0.1',()=>{net.connect(srv.address().port,'127.0.0.1');});
