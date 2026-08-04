const net=require('net');
const srv=net.createServer(sock=>{sock.on('data',d=>sock.write(d));sock.on('end',()=>sock.end());});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{c.write('echo-me');c.end();});
  let b='';c.on('data',d=>b+=d);c.on('close',()=>{console.log('got:'+b);srv.close();});
});
