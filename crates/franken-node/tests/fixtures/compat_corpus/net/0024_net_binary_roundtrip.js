const net=require('net');
const payload=Buffer.from([0,127,128,255,10,13]);
const srv=net.createServer(sock=>{sock.on('data',d=>sock.write(d));sock.on('end',()=>sock.end());});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1',()=>{c.write(payload);c.end();});
  const chunks=[];c.on('data',d=>chunks.push(d));
  c.on('close',()=>{console.log('hex:'+Buffer.concat(chunks).toString('hex'));srv.close();});
});
