const checks = [
  () => Buffer.alloc(2).writeUInt32BE(1, 0),
  () => Buffer.alloc(2).writeUInt8(256, 0),
  () => Buffer.alloc(2).writeInt8(-129, 0),
  () => Buffer.alloc(1).readUInt16BE(0),
];
for (const fn of checks) {
  try {
    fn();
    console.log('no-throw');
  } catch (e) {
    console.log(e instanceof RangeError);
  }
}
