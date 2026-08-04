const http=require('http');
const srv=http.createServer((req,res)=>{
  const q=req.url.split('?')[1]||'';res.end('q:'+q);
});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/p?alpha=1&beta=two'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log(b);srv.close();});
  });
});
