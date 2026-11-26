const http = require('http');
const srv = http.createServer((req, res) => {
  res.writeHead(404);
  res.end('no-such-route');
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/absent' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => {
      console.log('status:' + res.statusCode + ',msg:' + res.statusMessage + ',body:' + body);
      srv.close();
    });
  });
});
