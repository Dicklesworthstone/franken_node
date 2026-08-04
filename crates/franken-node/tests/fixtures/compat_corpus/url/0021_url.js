try {
  new URL('not a url');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError, e.code);
}
try {
  new URL('/path/only');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError);
}
