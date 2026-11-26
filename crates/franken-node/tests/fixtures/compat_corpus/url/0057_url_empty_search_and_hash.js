const u1 = new URL('https://ex.com/a?#');
const u2 = new URL('https://ex.com/a?');
const u3 = new URL('https://ex.com/a#');
console.log(JSON.stringify([u1.search, u1.hash, u1.href]));
console.log(JSON.stringify([u2.search, u2.hash, u2.href]));
console.log(JSON.stringify([u3.search, u3.hash, u3.href]));
