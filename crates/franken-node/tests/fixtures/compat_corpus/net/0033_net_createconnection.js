const net=require('net');
const srv=net.createServer(sock=>{sock.end('via-alias');});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.createConnection({port:srv.address().port,host:'127.0.0.1'});
  let b='';c.on('data',d=>b+=d);c.on('close',()=>{console.log(b);srv.close();});
});
