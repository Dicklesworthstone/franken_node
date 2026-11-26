const http = require('http');
let serverLog = '';
const srv = http.createServer((req, res) => {
  const before = res.writable + ':' + res.writableEnded;
  res.end('ok');
  const after = res.writableEnded;
  serverLog = 'before:' + before + ',after-ended:' + after;
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    res.resume();
    res.on('end', () => {
      console.log(serverLog);
      srv.close();
    });
  });
});
