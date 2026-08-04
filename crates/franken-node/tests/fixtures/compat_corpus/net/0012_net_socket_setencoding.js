const net=require('net');
const srv=net.createServer(sock=>{sock.end('text-data');});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  c.setEncoding('utf8');
  c.on('data',d=>console.log('type:'+typeof d+' v:'+d));c.on('close',()=>srv.close());
});
