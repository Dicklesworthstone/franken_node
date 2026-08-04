const t = setTimeout(() => {
  console.log('still-fired');
}, 10);
console.log('hasRef:' + t.hasRef());
t.unref();
console.log('afterUnref:' + t.hasRef());
t.ref();
console.log('afterRef:' + t.hasRef());
