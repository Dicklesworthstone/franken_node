const net = require('net');
const srv = net.createServer(() => {});
const before = srv.address();
srv.listen(0, '127.0.0.1', () => {
  const during = srv.address();
  srv.close(() => {
    const after = srv.address();
    console.log('before-null:' + (before === null) + ',during-ok:' + (during !== null && during.port > 0) + ',after-null:' + (after === null));
  });
});
