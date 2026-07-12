const net=require('net');
const srv=net.createServer(sock=>sock.end());
srv.listen(0,'127.0.0.1',()=>{
  const a=srv.address();
  console.log('family:'+a.family,'addr:'+a.address);
  srv.close();
});
