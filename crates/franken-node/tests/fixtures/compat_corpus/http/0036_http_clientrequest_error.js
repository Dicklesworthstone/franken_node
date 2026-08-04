const http=require('http');
const srv=http.createServer((req,res)=>{res.end();});
srv.listen(0,'127.0.0.1',()=>{
  const port=srv.address().port;
  srv.close(()=>{
    const rq=http.get({host:'127.0.0.1',port,path:'/'},()=>{});
    rq.on('error',e=>console.log('code:'+e.code));
  });
});
