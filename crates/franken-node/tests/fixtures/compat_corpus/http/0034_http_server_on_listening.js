const http=require('http');
const srv=http.createServer((req,res)=>{res.end();});
srv.on('listening',()=>{console.log('listening:'+srv.listening);srv.close();});
srv.listen(0,'127.0.0.1');
