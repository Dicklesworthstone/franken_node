const net=require('net');
const srv=net.createServer(sock=>sock.end());
srv.listen(0,'127.0.0.1',()=>{
  const before=srv.listening;
  srv.close(()=>{console.log('before:'+before+' after:'+srv.listening);});
});
