const net = require('net');
let finishFired = false;
let cbFired = false;
let serverGot = '';
const srv = net.createServer((sock) => {
  sock.on('data', (d) => { serverGot += d.toString(); });
  sock.on('end', () => sock.end());
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.on('finish', () => { finishFired = true; });
    c.end('final-bytes', () => { cbFired = true; });
  });
  c.on('close', () => {
    console.log('finish:' + finishFired + ',cb:' + cbFired + ',got:' + serverGot);
    srv.close();
  });
});
