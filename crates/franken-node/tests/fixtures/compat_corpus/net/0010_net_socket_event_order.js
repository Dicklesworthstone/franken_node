const net=require('net');
const srv=net.createServer(sock=>{sock.end('D');});
srv.listen(0,'127.0.0.1',()=>{
  const c=net.connect(srv.address().port,'127.0.0.1');
  const order=[];c.on('data',()=>order.push('data'));c.on('end',()=>order.push('end'));
  c.on('close',()=>{order.push('close');console.log(order.join(','));srv.close();});
});
