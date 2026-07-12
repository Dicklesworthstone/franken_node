const http=require('http');
let n=0;
const srv=http.createServer((req,res)=>{n+=1;res.end(String(n));});
srv.listen(0,'127.0.0.1',()=>{
  const port=srv.address().port;
  const one=(k,done)=>http.get({host:'127.0.0.1',port,path:'/'},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>done(b));});
  one(1,a=>one(2,b=>one(3,c=>{console.log(a+','+b+','+c);srv.close();})));
});
