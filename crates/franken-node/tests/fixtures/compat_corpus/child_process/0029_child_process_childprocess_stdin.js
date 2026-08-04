const cp = require('child_process');
const c = cp.spawn('cat');
let buf = '';
c.stdout.on('data', (d) => { buf += d.toString(); });
c.on('close', () => console.log('roundtrip:' + buf.trim()));
c.stdin.write('through-stdin');
c.stdin.end();
