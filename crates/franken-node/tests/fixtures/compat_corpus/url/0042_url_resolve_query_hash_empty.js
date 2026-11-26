const base = 'https://ex.com/a/b?old=0#prev';
console.log(new URL('?q=1', base).href);
console.log(new URL('#next', base).href);
console.log(new URL('', base).href);
