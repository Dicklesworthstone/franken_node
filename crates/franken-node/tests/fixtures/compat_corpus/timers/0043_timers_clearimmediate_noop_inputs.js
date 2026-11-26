const im = setImmediate(() => {
  console.log('ran');
  clearImmediate(im);
  clearImmediate(null);
  clearImmediate(undefined);
  console.log('noop-ok');
});
