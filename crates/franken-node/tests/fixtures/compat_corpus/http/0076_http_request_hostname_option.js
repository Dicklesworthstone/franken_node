const http = require('http');
const srv = http.createServer((req, res) => {
  res.end('hostname-ok:' + req.url);
});
srv.listen(0, '127.0.0.1', () => {
  const req = http.request(
    { hostname: '127.0.0.1', port: srv.address().port, path: '/via-hostname' },
    (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => { console.log(body); srv.close(); });
    }
  );
  req.end();
});
