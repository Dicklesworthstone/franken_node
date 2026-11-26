const sp1 = new URLSearchParams('?a=1&b=2');
const sp2 = new URLSearchParams('a&b=&=c&&d=1=2');
console.log(sp1.toString());
console.log(JSON.stringify(Array.from(sp2.entries())));
