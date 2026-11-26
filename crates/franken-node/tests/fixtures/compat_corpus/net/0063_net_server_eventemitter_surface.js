const net = require('net');
const srv = net.createServer();
let hits = 0;
const extra = () => { hits += 10; };
srv.on('connection', extra);
const countWithTwo = srv.listenerCount('connection');
srv.off('connection', extra);
const countAfterOff = srv.listenerCount('connection');
srv.once('connection', (sock) => {
  hits += 1;
  sock.end('once-ok');
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  let got = '';
  c.on('data', (d) => { got += d.toString(); });
  c.on('end', () => {
    console.log('counts:' + countWithTwo + ',' + countAfterOff + ',after-once:' + srv.listenerCount('connection') + ',hits:' + hits + ',got:' + got);
    srv.close();
  });
});
