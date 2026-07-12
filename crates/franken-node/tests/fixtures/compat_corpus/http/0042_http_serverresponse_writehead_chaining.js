const http=require('http');
const srv=http.createServer((req,res)=>{const r=res.writeHead(200);console.log('chain:'+(r===res));res.end();});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{res.resume();res.on('end',()=>srv.close());});
});
