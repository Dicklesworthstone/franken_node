const http=require('http');
const srv=http.createServer((req,res)=>{res.setHeader('X-Mixed-Case','V1');res.end();});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    console.log('h:'+res.headers['x-mixed-case']);res.resume();res.on('end',()=>srv.close());
  });
});
