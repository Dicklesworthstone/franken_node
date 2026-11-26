const net = require('net');
let srvStats = '';
let cliStats = '';
let closed = 0;
const finish = () => {
  closed += 1;
  if (closed === 2) {
    console.log(cliStats + ',' + srvStats);
    srv.close();
  }
};
const srv = net.createServer((sock) => {
  let rx = 0;
  sock.on('data', (d) => {
    rx += d.length;
    if (rx === 7) {
      sock.write('12345');
      sock.end('67890');
    }
  });
  sock.on('close', () => {
    srvStats = 'sr:' + sock.bytesRead + ',sw:' + sock.bytesWritten;
    finish();
  });
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.write('abc');
    c.write('defg');
  });
  c.on('data', () => {});
  c.on('close', () => {
    cliStats = 'cr:' + c.bytesRead + ',cw:' + c.bytesWritten;
    finish();
  });
});
