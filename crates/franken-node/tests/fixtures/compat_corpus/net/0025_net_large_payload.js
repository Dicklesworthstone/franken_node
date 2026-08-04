const net=require('net');
const payload='z'.repeat(65536);
const srv=net.createServer(sock=>{sock.end(payload);});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  let n=0;c.on('data',d=>n+=d.length);
  c.on('end',()=>{console.log('len:'+n);srv.close();});
});
