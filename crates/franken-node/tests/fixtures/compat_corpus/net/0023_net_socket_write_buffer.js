const net=require('net');
const srv=net.createServer(sock=>{let b='';sock.on('data',d=>b+=d);sock.on('end',()=>{console.log('same:'+(b==='XYXY'));sock.end();srv.close();});});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{c.write('XY');c.write(Buffer.from('XY'));c.end();});
});
