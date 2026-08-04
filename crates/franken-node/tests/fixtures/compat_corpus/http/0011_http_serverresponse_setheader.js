const http=require('http');
const srv=http.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end('{}');});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    console.log('ct:'+res.headers['content-type']);res.resume();res.on('end',()=>srv.close());
  });
});
