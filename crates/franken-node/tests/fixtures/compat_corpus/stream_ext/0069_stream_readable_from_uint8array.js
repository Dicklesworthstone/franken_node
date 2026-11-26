const { Readable } = require('stream');
(async () => {
  const bytes = new Uint8Array([65, 66, 67]);
  const asNums = await Readable.from(bytes).toArray();
  const asBufs = await Readable.from([bytes], { objectMode: false }).toArray();
  console.log(asNums.join(','));
  console.log(Buffer.concat(asBufs).toString('utf8'));
})();
