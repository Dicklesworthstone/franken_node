const http=require('http');
const srv=http.createServer((req,res)=>{res.end('h:'+req.headers['x-set-late']);});
srv.listen(0,'127.0.0.1',()=>{
  const rq=http.request({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log(b);srv.close();});
  });
  rq.setHeader('X-Set-Late','later');rq.end();
});
