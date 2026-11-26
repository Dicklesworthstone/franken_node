const list = [
  Buffer.from('b'),
  Buffer.from('ab'),
  Buffer.from(''),
  Buffer.from('a'),
  Buffer.from('aa'),
];
list.sort(Buffer.compare);
console.log(JSON.stringify(list.map((x) => x.toString('utf8'))));
