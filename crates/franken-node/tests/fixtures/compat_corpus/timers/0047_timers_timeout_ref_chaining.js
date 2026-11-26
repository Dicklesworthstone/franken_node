const t = setTimeout(() => {
  console.log('chained-fired');
}, 5);
console.log(t.unref() === t);
console.log(t.hasRef());
console.log(t.ref() === t);
console.log(t.hasRef());
