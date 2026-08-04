const net=require('net');
const srv=net.createServer();
srv.on('connection',sock=>{console.log('connection');sock.end();srv.close();});
srv.listen(0,'127.0.0.1',()=>{net.connect(srv.address().port,'127.0.0.1');});
