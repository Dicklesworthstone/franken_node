const http=require('http');
const srv=http.createServer((req,res)=>{res.end('host:'+(typeof req.headers.host==='string'&&req.headers.host.length>0));});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log(b);srv.close();});
  });
});
