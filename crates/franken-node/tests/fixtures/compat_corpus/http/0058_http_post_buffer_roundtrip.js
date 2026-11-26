const http = require('http');
const srv = http.createServer((req, res) => {
  const parts = [];
  req.on('data', (c) => parts.push(Buffer.from(c)));
  req.on('end', () => {
    res.end(Buffer.concat(parts));
  });
});
srv.listen(0, '127.0.0.1', () => {
  const p1 = Buffer.from([0x00, 0x11, 0x22, 0x7f]);
  const p2 = Buffer.from([0x80, 0xab, 0xcd, 0xff]);
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/bin', method: 'POST' },
    (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(Buffer.from(c)));
      res.on('end', () => {
        console.log('hex:' + Buffer.concat(chunks).toString('hex'));
        srv.close();
      });
    }
  );
  req.write(p1);
  req.end(p2);
});
