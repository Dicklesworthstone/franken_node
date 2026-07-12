const http=require('http');
const srv=http.createServer((req,res)=>{res.write('one-');res.write('two-');res.end('three');});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log('b:'+b);srv.close();});
  });
});
