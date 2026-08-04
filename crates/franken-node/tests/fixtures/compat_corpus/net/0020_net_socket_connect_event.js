const net=require('net');
const srv=net.createServer(sock=>{sock.end();});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  c.on('connect',()=>console.log('connect-event'));
  c.on('close',()=>srv.close());
});
