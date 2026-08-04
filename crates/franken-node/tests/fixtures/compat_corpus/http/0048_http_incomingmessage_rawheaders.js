const http=require('http');
const srv=http.createServer((req,res)=>{res.end('even:'+(req.rawHeaders.length%2===0)+' arr:'+Array.isArray(req.rawHeaders));});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log(b);srv.close();});
  });
});
