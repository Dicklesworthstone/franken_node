const http=require('http');
const srv=http.createServer((req,res)=>{
  res.setHeader('X-Check','1');console.log(res.hasHeader('x-check'),res.hasHeader('x-missing'));res.end();
});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{res.resume();res.on('end',()=>srv.close());});
});
