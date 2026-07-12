const {Transform} = require('stream');
const t = new Transform({
  objectMode: true,
  transform(obj, e, cb) { cb(null, {v: obj.v * 2}); }
});
t.on('data', (o) => console.log('v:' + o.v));
t.on('end', () => console.log('end'));
t.write({v: 3});
t.end({v: 5});
