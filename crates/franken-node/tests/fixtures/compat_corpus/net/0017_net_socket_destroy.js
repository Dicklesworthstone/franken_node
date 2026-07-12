const net=require('net');
const srv=net.createServer(sock=>{});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{c.destroy();});
  c.on('close',hadError=>{console.log('closed hadError:'+hadError);srv.close();});
});
