const checks = [
  () => Buffer.from([1, 2, 3]).swap16(),
  () => Buffer.from([1, 2, 3, 4, 5]).swap32(),
  () => Buffer.from([1, 2, 3, 4]).swap64(),
];
for (const fn of checks) {
  try {
    fn();
    console.log('no-throw');
  } catch (e) {
    console.log(e instanceof RangeError);
  }
}
