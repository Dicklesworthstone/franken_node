try {
  new URL('/rel/path', 'not-a-valid-base');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError);
}
