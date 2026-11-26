const right = Buffer.from('abcdef');
const n1 = right.copy(right, 2, 0, 4);
const left = Buffer.from('abcdef');
const n2 = left.copy(left, 0, 2, 6);
console.log(n1, right.toString('utf8'));
console.log(n2, left.toString('utf8'));
