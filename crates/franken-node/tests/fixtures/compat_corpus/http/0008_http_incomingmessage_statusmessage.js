const http=require('http');
const srv=http.createServer((req,res)=>{res.writeHead(418,'Teapot Here');res.end();});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    console.log(res.statusCode+':'+res.statusMessage);res.resume();res.on('end',()=>srv.close());
  });
});
