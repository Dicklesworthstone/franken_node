const http = require('http');
const srv = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(Buffer.from(c)));
  req.on('end', () => {
    const obj = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    obj.echo = true;
    const out = Buffer.from(JSON.stringify(obj), 'utf8');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', String(out.length));
    res.end(out);
  });
});
srv.listen(0, '127.0.0.1', () => {
  const sample = { greeting: 'héllo 世界 🚀', count: 3 };
  const body = Buffer.from(JSON.stringify(sample), 'utf8');
  const req = http.request(
    { host: '127.0.0.1', port: srv.address().port, path: '/utf8', method: 'POST' },
    (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(Buffer.from(c)));
      res.on('end', () => {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        console.log('match:' + (parsed.greeting === sample.greeting && parsed.echo === true && parsed.count === 3));
        srv.close();
      });
    }
  );
  req.end(body);
});
