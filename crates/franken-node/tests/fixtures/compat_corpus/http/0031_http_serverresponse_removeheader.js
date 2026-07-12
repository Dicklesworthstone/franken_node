const http=require('http');
const srv=http.createServer((req,res)=>{res.setHeader('X-Gone','yes');res.removeHeader('X-Gone');res.end();});
srv.listen(0,'127.0.0.1',()=>{
  http.get({host:'127.0.0.1',port:srv.address().port,path:'/'},res=>{
    console.log('gone:'+String(res.headers['x-gone']));res.resume();res.on('end',()=>srv.close());
  });
});
