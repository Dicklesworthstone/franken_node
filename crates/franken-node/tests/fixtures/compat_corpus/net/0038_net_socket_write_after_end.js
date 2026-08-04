const net=require('net');
const srv=net.createServer(sock=>{sock.on('data',()=>{});sock.on('end',()=>sock.end());});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{
    c.end();
    c.on('error',e=>{console.log('err:'+(e instanceof Error));srv.close();});
    try{const ok=c.write('late');console.log('write-returned:'+ok);}catch(e){console.log('threw:'+(e instanceof Error));srv.close();}
  });
});
