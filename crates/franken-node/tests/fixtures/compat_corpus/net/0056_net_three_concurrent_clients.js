const net = require('net');
const srv = net.createServer((sock) => {
  let buf = '';
  sock.on('data', (d) => {
    buf += d.toString();
    if (buf.endsWith('\n')) sock.end('E:' + buf.trim());
  });
});
srv.listen(0, '127.0.0.1', () => {
  const port = srv.address().port;
  const runClient = (msg) => new Promise((resolve) => {
    const c = net.connect(port, '127.0.0.1', () => c.write(msg + '\n'));
    let out = '';
    c.on('data', (d) => { out += d.toString(); });
    c.on('end', () => resolve(out));
  });
  Promise.all([runClient('c1'), runClient('c2'), runClient('c3')]).then((res) => {
    console.log(res.join('|'));
    srv.close();
  });
});
