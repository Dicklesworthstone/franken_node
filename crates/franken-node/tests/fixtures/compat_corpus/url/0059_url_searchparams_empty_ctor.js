const sp1 = new URLSearchParams();
const sp2 = new URLSearchParams('');
console.log(JSON.stringify(sp1.toString()), sp1.get('x'), sp1.has('x'));
console.log(JSON.stringify(sp2.toString()), Array.from(sp2.entries()).length);
