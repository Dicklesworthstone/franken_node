const net=require('net');
const a=net.createServer(s=>s.end());
const b=net.createServer(s=>s.end());
a.listen(0,'127.0.0.1',()=>{
  b.listen(0,'127.0.0.1',()=>{
    console.log('distinct:'+(a.address().port!==b.address().port));
    a.close();b.close();
  });
});
