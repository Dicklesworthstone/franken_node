const http=require('http');
const srv=http.createServer();
srv.on('request',(req,res)=>{res.end('via-event');});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log(b);srv.close();});
  });
});
