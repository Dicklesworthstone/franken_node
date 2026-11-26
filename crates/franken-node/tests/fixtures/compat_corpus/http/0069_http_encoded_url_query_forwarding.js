const http = require('http');
const srv = http.createServer((req, res) => {
  res.end(req.url);
});
srv.listen(0, '127.0.0.1', () => {
  const target = '/files/hello%20world?q=a%26b&k=1%2B2';
  http.get({ host: '127.0.0.1', port: srv.address().port, path: target }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => {
      console.log('exact:' + (body === target) + ',url:' + body);
      srv.close();
    });
  });
});
