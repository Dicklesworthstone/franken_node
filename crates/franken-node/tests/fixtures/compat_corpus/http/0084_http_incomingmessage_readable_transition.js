const http = require('http');
const srv = http.createServer((req, res) => {
  res.end('stream-data');
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    const before = res.readable;
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => {
      console.log('before:' + before + ',after:' + res.readable + ',body:' + body);
      srv.close();
    });
  });
});
