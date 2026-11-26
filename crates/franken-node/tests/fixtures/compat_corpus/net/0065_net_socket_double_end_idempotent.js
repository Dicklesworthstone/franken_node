const net = require('net');
let finishCount = 0;
const srv = net.createServer((sock) => {
  sock.on('data', () => {});
  sock.on('end', () => sock.end());
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.on('finish', () => { finishCount += 1; });
    c.end('once');
    c.end();
  });
  c.on('close', () => {
    console.log('finish-count:' + finishCount);
    srv.close();
  });
});
