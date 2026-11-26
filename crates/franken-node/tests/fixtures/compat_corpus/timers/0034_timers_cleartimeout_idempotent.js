let dropped = false;
const tDrop = setTimeout(() => { dropped = true; }, 10);
const tKeep = setTimeout(() => {
  console.log('kept-fired:dropped=' + dropped);
}, 30);
clearTimeout(tDrop);
clearTimeout(tDrop);
console.log('double-clear-ok:' + (typeof tKeep === 'object'));
