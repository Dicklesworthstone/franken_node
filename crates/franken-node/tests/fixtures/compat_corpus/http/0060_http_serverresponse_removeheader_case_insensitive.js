const http = require('http');
const srv = http.createServer((req, res) => {
  res.setHeader('X-Temp-Hdr', 'drop-me');
  const before = res.hasHeader('x-temp-hdr');
  res.removeHeader('X-TEMP-HDR');
  const after = res.hasHeader('x-temp-hdr');
  res.end('before:' + before + ',after:' + after);
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => {
      console.log(body + ',client-absent:' + (res.headers['x-temp-hdr'] === undefined));
      srv.close();
    });
  });
});
