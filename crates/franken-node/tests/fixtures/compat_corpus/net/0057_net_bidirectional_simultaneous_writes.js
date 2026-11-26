const net = require('net');
let serverRx = '';
let clientRx = '';
let closedCount = 0;
const srv = net.createServer((sock) => {
  sock.write('from-server');
  sock.on('data', (d) => { serverRx += d.toString(); });
  sock.on('end', () => sock.end());
  sock.on('close', () => {
    closedCount += 1;
    if (closedCount === 2) {
      console.log('srv:' + serverRx + ',cli:' + clientRx);
      srv.close();
    }
  });
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.end('from-client');
  });
  c.on('data', (d) => { clientRx += d.toString(); });
  c.on('close', () => {
    closedCount += 1;
    if (closedCount === 2) {
      console.log('srv:' + serverRx + ',cli:' + clientRx);
      srv.close();
    }
  });
});
