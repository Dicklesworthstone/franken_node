const net=require('net');
const srv=net.createServer(sock=>{sock.end();});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{
    console.log('unref-chain:'+(c.unref()===c),'ref-chain:'+(c.ref()===c));c.end();
  });
  c.on('close',()=>srv.close());
});
