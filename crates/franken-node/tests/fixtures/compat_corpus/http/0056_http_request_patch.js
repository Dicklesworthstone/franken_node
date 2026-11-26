const http = require('http');
const srv = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const parsed = JSON.parse(body);
    res.end(req.method + ':' + parsed.field + '=' + parsed.value);
  });
});
srv.listen(0, '127.0.0.1', () => {
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/doc/1', method: 'PATCH' },
    (res) => {
      let out = '';
      res.on('data', (c) => { out += c; });
      res.on('end', () => { console.log(out); srv.close(); });
    }
  );
  req.end(JSON.stringify({ field: 'name', value: 'updated' }));
});
