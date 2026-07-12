const t = setTimeout(() => {}, 10);
console.log(typeof t);
console.log(t === null);
clearTimeout(t);
console.log('cleared');
