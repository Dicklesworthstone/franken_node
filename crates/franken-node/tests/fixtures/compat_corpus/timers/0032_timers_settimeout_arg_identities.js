const obj = { id: 42 };
const arr = [1, 2];
setTimeout((a, b, c, d) => {
  console.log(a === null);
  console.log(b === undefined);
  console.log(c === obj);
  console.log(d === arr && d.length === 2);
}, 5, null, undefined, obj, arr);
