const sp = new URLSearchParams([
  ['k 1', 'v+1'],
  ['~!*()', 'a&b=c'],
  ['keep_-.*', 'ok'],
]);
console.log(sp.toString());
