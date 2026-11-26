const samples = [
  'mailto:user@example.com',
  'data:text/plain;base64,SGVsbG8=',
  'urn:ietf:rfc:2648',
];
for (const s of samples) {
  const u = new URL(s);
  console.log(JSON.stringify([u.protocol, u.hostname, u.pathname, u.origin]));
}
