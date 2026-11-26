const net = require('net');
let sockEnded = false;
let closeCalled = false;
const srv = net.createServer((sock) => {
  srv.close(() => {
    console.log('called:' + closeCalled + ',waited:' + sockEnded + ',listening:' + srv.listening);
  });
  closeCalled = true;
  setTimeout(() => {
    sockEnded = true;
    sock.end('bye');
  }, 20);
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  c.resume();
  c.on('end', () => c.end());
});
