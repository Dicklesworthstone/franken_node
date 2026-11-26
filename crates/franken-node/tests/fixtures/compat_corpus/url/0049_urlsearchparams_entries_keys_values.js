const sp = new URLSearchParams('b=1&a=2&b=3');
console.log(JSON.stringify(Array.from(sp.entries())));
console.log(JSON.stringify(Array.from(sp.keys())));
console.log(JSON.stringify(Array.from(sp.values())));
