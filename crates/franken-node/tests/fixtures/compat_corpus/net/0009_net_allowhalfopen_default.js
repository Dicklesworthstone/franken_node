const net=require('net');
const srv=net.createServer(sock=>{sock.on('close',()=>{console.log('server-sock-closed');srv.close();});});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{c.end();});
});
