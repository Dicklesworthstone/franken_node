const net = require('net');
const srv = net.createServer((sock) => {
  sock.on('data', (d) => sock.end('lh:' + d.toString()));
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, 'localhost', () => {
    c.write('ping');
  });
  let got = '';
  c.on('data', (d) => { got += d.toString(); });
  c.on('end', () => {
    console.log(got);
    srv.close();
  });
});
