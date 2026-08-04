const {Readable} = require('stream');
(async () => {
  const arr = await Readable.from(['t1', 't2']).toArray();
  console.log(Array.isArray(arr) + ':' + arr.length + ':' + arr.join('+'));
})();
