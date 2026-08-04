const b = Buffer.alloc(2);
try {
  b.readUInt32LE(0);
  console.log('no-throw');
} catch (e) {
  console.log(e instanceof RangeError);
  console.log(String(e.code));
}
