const tls = require('tls');
const tldBad = tls.checkServerIdentity('foo.com', { subject: { CN: '*.com' }, subjectaltname: 'DNS:*.com' });
const idnBad = tls.checkServerIdentity('xn--foo.example.com', {
  subject: { CN: 'xn--*.example.com' },
  subjectaltname: 'DNS:xn--*.example.com',
});
console.log('tld-err:' + (tldBad instanceof Error) + ',idn-err:' + (idnBad instanceof Error));
