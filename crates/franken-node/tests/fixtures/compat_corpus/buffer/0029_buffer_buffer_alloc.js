try {
  Buffer.alloc(-1);
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof RangeError);
  console.log(String(e.code));
}
