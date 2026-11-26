const net = require('net');
const srv = net.createServer((sock) => {
  sock.write('part1-');
  sock.write('part2-');
  sock.end('part3');
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  c.pause();
  const events = [];
  let body = '';
  c.on('data', (d) => {
    if (events.length === 0) events.push('data');
    body += d.toString();
  });
  c.on('end', () => {
    events.push('end');
    console.log('events:' + events.join(',') + ',body:' + body);
    srv.close();
  });
  setTimeout(() => c.resume(), 20);
});
