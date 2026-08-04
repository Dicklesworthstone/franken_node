const j = Buffer.from([1, 2, 255]).toJSON();
console.log(j.type);
console.log(j.data.join(','));
