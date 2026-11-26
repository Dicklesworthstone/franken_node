const got = [];
setTimeout(() => {
  got.push('null');
  if (got.length === 2) console.log(got.join(','));
}, null);
setTimeout(() => {
  got.push('false');
  if (got.length === 2) console.log(got.join(','));
}, false);
console.log('sync');
