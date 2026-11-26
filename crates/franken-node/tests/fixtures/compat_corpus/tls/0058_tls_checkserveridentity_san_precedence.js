const tls = require('tls');
const cert = {
  subject: { CN: 'legacy.example.com' },
  subjectaltname: 'DNS:modern.example.com',
};
const sanOk = tls.checkServerIdentity('modern.example.com', cert);
const cnIgnored = tls.checkServerIdentity('legacy.example.com', cert);
console.log(
  'san-ok:' + (sanOk === undefined) +
  ',cn-rejected:' + (cnIgnored instanceof Error) +
  ',code:' + (cnIgnored && cnIgnored.code)
);
