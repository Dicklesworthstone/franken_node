const net = require('net');
const srv = net.createServer(() => {});
srv.listen(0, '127.0.0.1', () => {
  let openState = '';
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    openState = c.destroyed + ':' + c.readable + ':' + c.writable;
    c.destroy();
  });
  c.on('close', (hadError) => {
    const closedState = c.destroyed + ':' + c.readable + ':' + c.writable;
    console.log('open:' + openState + ',closed:' + closedState + ',hadError:' + hadError);
    srv.close();
  });
});
