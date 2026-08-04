const http=require('http');
const srv=http.createServer((req,res)=>{res.setHeader('Content-Length','5');res.end(req.method==='HEAD'?undefined:'12345');});
srv.listen(0,'127.0.0.1',()=>{
  const rq=http.request({host:'127.0.0.1',port:srv.address().port,method:'HEAD',path:'/'},res=>{
    let n=0;res.on('data',c=>n+=c.length);res.on('end',()=>{console.log('cl:'+res.headers['content-length']+' bytes:'+n);srv.close();});
  });
  rq.end();
});
