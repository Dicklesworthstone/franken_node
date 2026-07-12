const http=require('http');
const srv=http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>res.end(b.toUpperCase()));});
srv.listen(0,'127.0.0.1',()=>{
  const rq=http.request({host:'127.0.0.1',port:srv.address().port,method:'POST',path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log('echo:'+b);srv.close();});
  });
  rq.end('shout this');
});
