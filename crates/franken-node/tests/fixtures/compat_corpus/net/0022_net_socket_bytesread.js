const net=require('net');
const srv=net.createServer(sock=>{sock.end('abcdef');});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  c.on('data',()=>{});
  c.on('close',()=>{console.log('read:'+c.bytesRead);srv.close();});
});
