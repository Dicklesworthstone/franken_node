const http=require('http');
const srv=http.createServer((req,res)=>{res.end();});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let n=0;res.on('data',c=>n+=c.length);res.on('end',()=>{console.log('bytes:'+n);srv.close();});
  });
});
