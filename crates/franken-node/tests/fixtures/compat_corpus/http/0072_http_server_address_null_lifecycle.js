const http = require('http');
const srv = http.createServer((req, res) => res.end('ok'));
const before = srv.address();
srv.listen(0, '127.0.0.1', () => {
  const during = srv.address();
  srv.close(() => {
    const after = srv.address();
    console.log('before-null:' + (before === null) + ',during-port:' + (during !== null && during.port > 0) + ',after-null:' + (after === null));
  });
});
