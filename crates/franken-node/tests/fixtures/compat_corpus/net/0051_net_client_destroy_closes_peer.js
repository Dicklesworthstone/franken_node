const net = require('net');
let serverClosed = false;
const srv = net.createServer((sock) => {
  sock.on('close', () => {
    serverClosed = true;
    console.log('server-closed:' + serverClosed);
    srv.close();
  });
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.destroy();
  });
});
