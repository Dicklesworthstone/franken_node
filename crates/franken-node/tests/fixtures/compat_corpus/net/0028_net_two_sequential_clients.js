const net=require('net');
let n=0;
const srv=net.createServer(sock=>{n+=1;sock.end('client-'+n);});
srv.listen(0,'127.0.0.1',()=>{
  const port=srv.address().port;
  const go=done=>{const c=net.connect(port,'127.0.0.1');let b='';c.on('data',d=>b+=d);c.on('close',()=>done(b));};
  go(a=>{go(b=>{console.log(a+'|'+b);srv.close();});});
});
