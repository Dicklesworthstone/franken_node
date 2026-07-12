const net=require('net');
const srv=net.createServer(sock=>{sock.on('data',()=>{});sock.on('end',()=>sock.end());});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{c.write('12345');c.end();});
  c.on('close',()=>{console.log('written>=5:'+(c.bytesWritten>=5));srv.close();});
});
