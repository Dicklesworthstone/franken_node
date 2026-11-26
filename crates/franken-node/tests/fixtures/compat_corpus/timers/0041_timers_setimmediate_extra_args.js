setImmediate((a, b, c) => {
  console.log(a + '|' + b + '|' + c);
}, 'imm', 99, false);
