const net = require('net');
const srv = net.createServer((sock) => { sock.end('opts-listen'); });
srv.listen({ port: 0, host: '127.0.0.1' }, () => {
  const addr = srv.address();
  const c = net.connect(addr.port, '127.0.0.1');
  let got = '';
  c.on('data', (d) => { got += d.toString(); });
  c.on('end', () => {
    console.log('addr:' + addr.address + ',got:' + got);
    srv.close();
  });
});
