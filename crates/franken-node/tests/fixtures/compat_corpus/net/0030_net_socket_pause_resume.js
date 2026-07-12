const net=require('net');
const srv=net.createServer(sock=>{sock.end('deferred');});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  c.pause();
  let b='';c.on('data',d=>b+=d);
  setTimeout(()=>{c.resume();},20);
  c.on('end',()=>{console.log('after-resume:'+b);srv.close();});
});
