const http=require('http');
const srv=http.createServer((req,res)=>{res.end();});
srv.listen(0,'127.0.0.1',()=>{
  const a=srv.address();
  console.log(typeof a.port==='number',a.port>0,a.address==='127.0.0.1');
  srv.close();
});
