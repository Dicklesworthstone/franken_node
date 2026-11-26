const http = require('http');
const srv = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    res.end(req.method + '|' + req.url + '|' + req.headers['x-src'] + '|' + body);
  });
});
srv.listen(0, '127.0.0.1', () => {
  const url = 'http://127.0.0.1:' + srv.address().port + '/submit?mode=fast';
  const req = http.request(url, { method: 'POST', headers: { 'X-Src': 'url-opts' } }, (res) => {
    let out = '';
    res.on('data', (c) => { out += c; });
    res.on('end', () => { console.log(out); srv.close(); });
  });
  req.end('data-70');
});
