const http = require('http');
const srv = http.createServer((req, res) => {
  res.end('hdr:' + req.headers['x-get-tag'] + ',url:' + req.url);
});
srv.listen(0, '127.0.0.1', () => {
  const url = 'http://127.0.0.1:' + srv.address().port + '/check';
  http.get(url, { headers: { 'X-Get-Tag': 'g77' } }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => { console.log(body); srv.close(); });
  });
});
