const b = Buffer.from([1, 2, 3, 2, 1, 2]);
console.log(b.lastIndexOf(2));
console.log(b.lastIndexOf(2, 4));
console.log(b.lastIndexOf(2, 2));
console.log(b.lastIndexOf(2, -2));
console.log(b.lastIndexOf(9));
