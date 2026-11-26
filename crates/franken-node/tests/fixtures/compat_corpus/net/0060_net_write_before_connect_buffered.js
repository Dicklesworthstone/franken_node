const net = require('net');
const srv = net.createServer((sock) => {
  let rx = '';
  sock.on('data', (d) => {
    rx += d.toString();
    if (rx.endsWith('\n')) sock.end('got:' + rx.trim());
  });
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  c.write('queued-1-');
  c.write('queued-2\n');
  let out = '';
  c.on('data', (d) => { out += d.toString(); });
  c.on('end', () => {
    console.log(out);
    srv.close();
  });
});
