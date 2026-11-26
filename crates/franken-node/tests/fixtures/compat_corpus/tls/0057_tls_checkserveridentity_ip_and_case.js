const tls = require('tls');
const cert = {
  subject: { CN: 'example.com' },
  subjectaltname: 'DNS:API.Example.COM, IP Address:127.0.0.1',
};
const dnsCi = tls.checkServerIdentity('api.example.com', cert);
const ipOk = tls.checkServerIdentity('127.0.0.1', cert);
const ipBad = tls.checkServerIdentity('127.0.0.2', cert);
console.log(
  'dns-ci:' + (dnsCi === undefined) +
  ',ip-ok:' + (ipOk === undefined) +
  ',ip-bad:' + (ipBad instanceof Error)
);
