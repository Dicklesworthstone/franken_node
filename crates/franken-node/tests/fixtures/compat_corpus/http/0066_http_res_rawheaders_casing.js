const http = require('http');
const srv = http.createServer((req, res) => {
  res.setHeader('X-Server-Tag', 'TagValue');
  res.end('ok');
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, (res) => {
    let foundKey = '';
    let foundVal = '';
    for (let i = 0; i < res.rawHeaders.length; i += 2) {
      if (res.rawHeaders[i].toLowerCase() === 'x-server-tag') {
        foundKey = res.rawHeaders[i];
        foundVal = res.rawHeaders[i + 1];
      }
    }
    res.resume();
    res.on('end', () => {
      console.log('raw:' + foundKey + '=' + foundVal + ',lower:' + res.headers['x-server-tag']);
      srv.close();
    });
  });
});
