const http = require('http');
const total = 65536;
const chunkSize = 8192;
const srv = http.createServer((req, res) => {
  for (let off = 0; off < total; off += chunkSize) {
    const buf = Buffer.alloc(chunkSize);
    for (let i = 0; i < chunkSize; i++) buf[i] = (off + i) & 0xff;
    res.write(buf);
  }
  res.end();
});
srv.listen(0, '127.0.0.1', () => {
  http.get({ host: '127.0.0.1', port: srv.address().port, path: '/big' }, (res) => {
    const parts = [];
    res.on('data', (c) => parts.push(Buffer.from(c)));
    res.on('end', () => {
      const full = Buffer.concat(parts);
      let ok = full.length === total;
      for (let i = 0; ok && i < total; i++) {
        if (full[i] !== (i & 0xff)) ok = false;
      }
      console.log('len:' + full.length + ',exact:' + ok);
      srv.close();
    });
  });
});
