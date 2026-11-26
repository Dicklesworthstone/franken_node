const samples = [
  'ws://host.test:80/sock',
  'ws://host.test:81/sock',
  'wss://host.test:443/sock',
  'ftp://files.test:21/pub/a.bin',
];
for (const s of samples) {
  const u = new URL(s);
  console.log(JSON.stringify([u.protocol, u.hostname, u.port, u.pathname, u.origin]));
}
