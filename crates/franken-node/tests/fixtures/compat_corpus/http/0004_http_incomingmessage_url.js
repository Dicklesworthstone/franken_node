const http=require('http');
const srv=http.createServer((req,res)=>{res.end(req.url);});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/a/b?k=v&x=1'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log('url:'+b);srv.close();});
  });
});
