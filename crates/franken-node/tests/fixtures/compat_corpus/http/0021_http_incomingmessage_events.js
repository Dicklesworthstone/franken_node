const http=require('http');
const srv=http.createServer((req,res)=>{res.end('payload');});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    const order=[];res.on('data',()=>order.push('data'));res.on('end',()=>{order.push('end');console.log(order.join(','));srv.close();});
  });
});
