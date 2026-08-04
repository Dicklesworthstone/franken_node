try {
  Buffer.from('abc').toString('bogus');
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof TypeError);
  console.log(String(e.code));
}
