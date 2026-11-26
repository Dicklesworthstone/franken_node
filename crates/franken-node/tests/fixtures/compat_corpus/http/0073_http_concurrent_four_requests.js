const http = require('http');
const srv = http.createServer((req, res) => {
  res.end('resp:' + req.url);
});
srv.listen(0, '127.0.0.1', () => {
  const port = srv.address().port;
  const paths = ['/one', '/two', '/three', '/four'];
  const fetchOne = (p) => new Promise((resolve) => {
    http.get({ host: '127.0.0.1', port, path: p }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve(body));
    });
  });
  Promise.all(paths.map(fetchOne)).then((results) => {
    console.log(results.join('|'));
    srv.close();
  });
});
