const sp = new URLSearchParams([
  ['a', '1'],
  ['a', '2'],
  ['b', 'hello world'],
]);
console.log(sp.toString());
console.log(JSON.stringify(sp.getAll('a')));
console.log(sp.get('b'));
