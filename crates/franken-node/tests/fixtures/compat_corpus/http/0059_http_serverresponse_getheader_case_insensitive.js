const http = require('http');
const srv = http.createServer((req, res) => {
  res.setHeader('X-Custom-Id', 'token-77');
  const lower = res.getHeader('x-custom-id');
  const upper = res.getHeader('X-CUSTOM-ID');
  const missing = res.getHeader('x-not-set');
  res.end('lower:' + lower + ',upper:' + upper + ',missing:' + (missing === undefined));
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => { console.log(body); srv.close(); });
  });
});
