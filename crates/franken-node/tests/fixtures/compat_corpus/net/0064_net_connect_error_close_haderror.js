const net = require('net');
const srv = net.createServer(() => {});
srv.listen(0, '127.0.0.1', () => {
  const closedPort = srv.address().port;
  srv.close(() => {
    const events = [];
    const c = net.connect(closedPort, '127.0.0.1');
    c.on('error', (err) => events.push('err:' + err.code));
    c.on('close', (hadError) => {
      events.push('close:' + hadError);
      console.log(events.join(','));
    });
  });
});
