const net = require('net');
const srv = net.createServer((sock) => { sock.end(); });
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  const before = c.connecting;
  c.on('connect', () => {
    const after = c.connecting;
    console.log('before:' + before + ',after:' + after);
    c.end();
  });
  c.on('close', () => srv.close());
});
