const http = require('http');
const srv = http.createServer((req, res) => {
  res.setHeader('X-List', ['v1', 'v2']);
  const got = res.getHeader('x-list');
  res.end('is-arr:' + Array.isArray(got) + ',vals:' + (Array.isArray(got) ? got.join('|') : String(got)));
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    let body = '';
    res.on('data', (c) => { body += c; });
    res.on('end', () => { console.log(body); srv.close(); });
  });
});
