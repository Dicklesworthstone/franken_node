const b = Buffer.from([10, 20, 30]);
console.log([...b.keys()].join(','));
console.log([...b.values()].join(','));
console.log([...b.entries()].map(e => e.join(':')).join(','));
