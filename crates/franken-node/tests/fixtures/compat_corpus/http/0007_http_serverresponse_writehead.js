const http=require('http');
const srv=http.createServer((req,res)=>{res.writeHead(404);res.end('nope');});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    console.log('status:'+res.statusCode);res.resume();res.on('end',()=>srv.close());
  });
});
