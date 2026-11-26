const http = require('http');
const total = 65536;
const chunkSize = 8192;
const srv = http.createServer((req, res) => {
  const parts = [];
  req.on('data', (c) => parts.push(Buffer.from(c)));
  req.on('end', () => {
    const full = Buffer.concat(parts);
    let ok = full.length === total;
    for (let i = 0; ok && i < total; i++) {
      if (full[i] !== ((i * 7 + 3) & 0xff)) ok = false;
    }
    res.end('len:' + full.length + ',exact:' + ok);
  });
});
srv.listen(0, '127.0.0.1', () => {
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/upload', method: 'POST' },
    (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => { console.log(body); srv.close(); });
    }
  );
  for (let off = 0; off < total; off += chunkSize) {
    const buf = Buffer.alloc(chunkSize);
    for (let i = 0; i < chunkSize; i++) buf[i] = ((off + i) * 7 + 3) & 0xff;
    req.write(buf);
  }
  req.end();
});
