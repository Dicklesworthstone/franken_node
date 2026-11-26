const names = [
  'utf8',
  'utf-8',
  'utf16le',
  'ucs2',
  'latin1',
  'binary',
  'ascii',
  'hex',
  'base64',
  'base64url',
  'utf32',
  '',
];
console.log(JSON.stringify(names.map((n) => Buffer.isEncoding(n))));
