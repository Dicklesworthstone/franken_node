const http = require('http');
const srv = http.createServer((req, res) => {
  res.setHeader('X-Color', 'red');
  res.setHeader('X-Keep', 'yes');
  res.writeHead(200, { 'x-color': 'blue' });
  res.end('ok');
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    res.resume();
    res.on('end', () => {
      console.log('color:' + res.headers['x-color'] + ',keep:' + res.headers['x-keep']);
      srv.close();
    });
  });
});
