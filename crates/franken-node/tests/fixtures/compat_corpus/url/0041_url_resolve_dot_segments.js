console.log(new URL('./c', 'https://ex.com/a/b').href);
console.log(new URL('../c', 'https://ex.com/a/b/d').href);
console.log(new URL('/a/b/../c/./d', 'https://ex.com/').href);
console.log(new URL('.', 'https://ex.com/a/b/c').href);
