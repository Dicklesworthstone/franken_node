const cp = require('child_process');
const c = cp.spawn('cat');
const chunks = [];
c.stdout.on('data', (d) => chunks.push(Buffer.from(d)));
c.on('close', (code) => {
  const all = Buffer.concat(chunks);
  console.log('text:' + all.toString('utf8'));
  console.log('code:' + code);
});
c.stdin.write('alpha-');
c.stdin.write(Buffer.from('beta-'));
c.stdin.write('gamma');
c.stdin.end();
