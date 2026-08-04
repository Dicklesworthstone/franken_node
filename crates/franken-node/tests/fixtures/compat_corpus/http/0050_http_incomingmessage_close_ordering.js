const http=require('http');
const srv=http.createServer((req,res)=>{res.end('bye');});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/',agent:false},res=>{
    const order=[];res.on('end',()=>order.push('end'));
    res.on('close',()=>{order.push('close');console.log(order.join(','));srv.close();});
    res.resume();
  });
});
