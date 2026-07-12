const net=require('net');
const srv=net.createServer(sock=>sock.end());
srv.listen(0,'127.0.0.1',()=>{
  const port=srv.address().port;
  srv.close(()=>{
    const c=net.connect(port,'127.0.0.1');
    c.on('error',e=>console.log('code:'+e.code));
  });
});
