const http = require('http');
const srv = http.createServer((req, res) => {
  res.setHeader('Allow', 'GET, POST, OPTIONS');
  res.writeHead(204);
  res.end(req.method);
});
srv.listen(0, '127.0.0.1', () => {
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/resource', method: 'OPTIONS' },
    (res) => {
      res.resume();
      res.on('end', () => {
        console.log('status:' + res.statusCode + ',allow:' + res.headers.allow);
        srv.close();
      });
    }
  );
  req.end();
});
