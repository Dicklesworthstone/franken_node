const net=require('net');
const srv=net.createServer(sock=>{sock.end('from-server');});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  let b='';c.on('data',d=>b+=d);c.on('end',()=>{console.log('client-saw:'+b);srv.close();});
});
