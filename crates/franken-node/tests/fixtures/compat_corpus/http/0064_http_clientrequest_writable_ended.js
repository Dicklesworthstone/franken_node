const http = require('http');
const srv = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => res.end(body));
});
srv.listen(0, '127.0.0.1', () => {
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/', method: 'POST' },
    (res) => {
      let out = '';
      res.on('data', (c) => { out += c; });
      res.on('end', () => {
        console.log('before:' + before + ',after-ended:' + afterEnded + ',out:' + out);
        srv.close();
      });
    }
  );
  const before = req.writable + ':' + req.writableEnded;
  req.end('payload');
  const afterEnded = req.writableEnded;
});
