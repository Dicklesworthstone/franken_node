console.log(new URL('../x', 'http://example.com/a/b/c').pathname);
console.log(new URL('../../y', 'http://example.com/a/b/c').pathname);
console.log(new URL('../../../../z', 'http://example.com/a/b/c').pathname);
