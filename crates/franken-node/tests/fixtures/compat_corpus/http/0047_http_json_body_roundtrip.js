const http=require('http');
const srv=http.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify([1,'two',true,null]));});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{const v=JSON.parse(b);console.log(v.length,v[0],v[1],v[2],v[3]);srv.close();});
  });
});
