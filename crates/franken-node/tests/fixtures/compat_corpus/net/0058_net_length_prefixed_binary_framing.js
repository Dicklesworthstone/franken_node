const net = require('net');
function encodeFrame(payload) {
  const body = Buffer.from(payload, 'utf8');
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(body.length, 0);
  return Buffer.concat([hdr, body]);
}
function decodeFrames(buf) {
  const out = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = buf.readUInt32BE(off);
    if (off + 4 + len > buf.length) break;
    off += 4;
    out.push(buf.subarray(off, off + len).toString('utf8'));
    off += len;
  }
  return out;
}
const srv = net.createServer((sock) => {
  const chunks = [];
  sock.on('data', (d) => {
    chunks.push(Buffer.from(d));
    const frames = decodeFrames(Buffer.concat(chunks));
    if (frames.length === 3) {
      const reply = Buffer.concat(frames.map((f) => encodeFrame(f.toUpperCase())));
      sock.end(reply);
    }
  });
});
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1', () => {
    c.write(encodeFrame('one'));
    c.write(encodeFrame('two-frame'));
    c.write(encodeFrame('three'));
  });
  const chunks = [];
  c.on('data', (d) => chunks.push(Buffer.from(d)));
  c.on('end', () => {
    console.log('frames:' + decodeFrames(Buffer.concat(chunks)).join('|'));
    srv.close();
  });
});
