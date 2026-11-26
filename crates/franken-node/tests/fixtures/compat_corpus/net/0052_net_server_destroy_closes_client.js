const net = require('net');
const srv = net.createServer((sock) => {
  sock.destroy();
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  c.on('close', () => {
    console.log('client-closed:true');
    srv.close();
  });
});
