const net = require('net');
const sample = 'café 日本語 🌍';
const expectedLen = sample.length;
const srv = net.createServer((sock) => {
  sock.setEncoding('utf8');
  let rx = '';
  sock.on('data', (s) => {
    rx += s;
    if (rx.length >= expectedLen) sock.end(rx);
  });
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.write(sample);
  });
  c.setEncoding('utf8');
  let out = '';
  c.on('data', (s) => { out += s; });
  c.on('end', () => {
    console.log('match:' + (out === sample) + ',chars:' + out.length);
    srv.close();
  });
});
