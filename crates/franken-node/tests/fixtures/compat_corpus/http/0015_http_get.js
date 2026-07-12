const http=require('http');
let n=0;
const srv=http.createServer((req,res)=>{n+=1;res.end('r'+n);});
srv.listen(0,'127.0.0.1',()=>{
  const port=srv.address().port;
  http.get({host:'127.0.0.1',port,path:'/'},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>{
    console.log('first:'+b);
    http.get({host:'127.0.0.1',port,path:'/'},res2=>{let b2='';res2.on('data',c=>b2+=c);res2.on('end',()=>{console.log('second:'+b2);srv.close();});});
  });});
});
