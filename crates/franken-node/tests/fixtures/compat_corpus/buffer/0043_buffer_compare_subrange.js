const a = Buffer.from([1, 2, 3, 4, 5]);
const b = Buffer.from([9, 2, 3, 8, 5]);
console.log(a.compare(b, 1, 3, 1, 3));
console.log(a.compare(b, 1, 4, 1, 4));
console.log(a.compare(b, 0, 1, 0, 1));
console.log(a.compare(b, 4, 5, 4, 5));
