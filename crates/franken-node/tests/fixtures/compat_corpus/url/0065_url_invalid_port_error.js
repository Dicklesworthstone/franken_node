try {
  new URL('http://example.com:99999/');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError);
}
