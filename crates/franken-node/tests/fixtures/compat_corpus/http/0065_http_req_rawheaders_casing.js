const http = require('http');
const srv = http.createServer((req, res) => {
  let foundKey = '';
  let foundVal = '';
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'x-mixed-case') {
      foundKey = req.rawHeaders[i];
      foundVal = req.rawHeaders[i + 1];
    }
  }
  res.end('raw:' + foundKey + '=' + foundVal + ',lower:' + req.headers['x-mixed-case']);
});
srv.listen(0, '127.0.0.1', () => {
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/', headers: { 'X-Mixed-Case': 'ValOne' } },
    (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => { console.log(body); srv.close(); });
    }
  );
  req.end();
});
