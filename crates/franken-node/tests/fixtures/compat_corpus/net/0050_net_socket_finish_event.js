const net = require('net');
let finished = 0;
const srv = net.createServer((sock) => {
  sock.on('data', () => {});
  sock.on('end', () => sock.end());
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.write('hello');
    c.end();
  });
  c.on('finish', () => { finished += 1; });
  c.on('close', () => {
    console.log('finish-count:' + finished);
    srv.close();
  });
});
