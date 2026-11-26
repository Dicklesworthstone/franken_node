const http = require('http');
const srv = http.createServer((req, res) => {
  res.writeHead(201, { 'X-Mode': 'two-arg' });
  res.end('done');
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    res.resume();
    res.on('end', () => {
      console.log('status:' + res.statusCode + ',msg:' + res.statusMessage + ',mode:' + res.headers['x-mode']);
      srv.close();
    });
  });
});
