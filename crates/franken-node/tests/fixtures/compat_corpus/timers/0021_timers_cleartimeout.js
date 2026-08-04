const t = setTimeout(() => {
  console.log('fired-once');
  clearTimeout(t);
  clearTimeout(undefined);
  clearTimeout(null);
  console.log('clears-ok');
}, 10);
