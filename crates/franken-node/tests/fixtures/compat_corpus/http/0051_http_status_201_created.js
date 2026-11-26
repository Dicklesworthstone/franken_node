const http = require('http');
const srv = http.createServer((req, res) => {
  res.writeHead(201);
  res.end('created-item');
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/items' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => {
      console.log('status:' + res.statusCode + ',msg:' + res.statusMessage + ',body:' + body);
      srv.close();
    });
  });
});
