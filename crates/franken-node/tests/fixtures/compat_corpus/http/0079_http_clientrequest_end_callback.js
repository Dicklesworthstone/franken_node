const http = require('http');
const srv = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => res.end('got:' + body));
});
srv.listen(0, '127.0.0.1', () => {
  let endCbFired = false;
  let respBody = '';
  let finished = 0;
  const maybeDone = () => {
    finished += 1;
    if (finished === 2) {
      console.log('endcb:' + endCbFired + ',resp:' + respBody);
      srv.close();
    }
  };
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/cb', method: 'POST' },
    (res) => {
      res.on('data', (c) => { respBody += c; });
      res.on('end', maybeDone);
    }
  );
  req.end('final-chunk', () => {
    endCbFired = true;
    maybeDone();
  });
});
