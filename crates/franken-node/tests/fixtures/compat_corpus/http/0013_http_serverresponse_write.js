const http=require('http');
const srv=http.createServer((req,res)=>{res.write('AB');setTimeout(()=>{res.end('CD');},10);});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log('b:'+b+' te:'+res.headers['transfer-encoding']);srv.close();});
  });
});
