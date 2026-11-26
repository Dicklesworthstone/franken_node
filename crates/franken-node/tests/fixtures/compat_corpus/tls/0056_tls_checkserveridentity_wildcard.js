const tls = require('tls');
const cert = { subject: { CN: '*.example.com' }, subjectaltname: 'DNS:*.example.com' };
const subOk = tls.checkServerIdentity('api.example.com', cert);
const deepBad = tls.checkServerIdentity('a.b.example.com', cert);
const apexBad = tls.checkServerIdentity('example.com', cert);
console.log(
  'sub:' + (subOk === undefined) +
  ',deep:' + (deepBad instanceof Error) +
  ',apex:' + (apexBad instanceof Error)
);
