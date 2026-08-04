const http=require('http');
const srv=http.createServer((req,res)=>{res.end('url-form:'+req.url);});
srv.listen(0,'127.0.0.1',()=>{
  http.get('http://127.0.0.1:'+srv.address().port+'/p?q=1',res=>{
    let b='';res.on('data',c=>b+=c);res.on('end',()=>{console.log(b);srv.close();});
  });
});
