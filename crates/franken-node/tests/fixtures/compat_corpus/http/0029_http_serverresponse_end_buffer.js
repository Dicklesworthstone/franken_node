const http=require('http');
const payload=Buffer.from([0,1,2,250,251,252]);
const srv=http.createServer((req,res)=>{res.end(payload);});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{console.log('hex:'+Buffer.concat(chunks).toString('hex'));srv.close();});
  });
});
