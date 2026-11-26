const http = require('http');
const srv = http.createServer((req, res) => {
  const payload = 'fixed-length-body';
  res.setHeader('Content-Length', String(Buffer.byteLength(payload)));
  res.end(payload);
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => {
      console.log('cl:' + res.headers['content-length'] + ',te-undef:' + (res.headers['transfer-encoding'] === undefined) + ',body:' + body);
      srv.close();
    });
  });
});
