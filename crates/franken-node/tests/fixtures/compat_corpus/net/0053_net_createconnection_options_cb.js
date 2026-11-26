const net = require('net');
const srv = net.createServer((sock) => {
  sock.on('data', (d) => sock.end('echo:' + d.toString()));
});
srv.listen(0, '127.0.0.1', () => {
  let cbCalled = false;
  let got = '';
  const c = net.createConnection({ port: srv.address().port, host: '127.0.0.1' }, () => {
    cbCalled = true;
    c.write('via-opts');
  });
  c.on('data', (d) => { got += d.toString(); });
  c.on('end', () => {
    console.log('cb:' + cbCalled + ',got:' + got);
    srv.close();
  });
});
